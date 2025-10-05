#!/usr/bin/env python3
"""
ANTI-RANSOMWARE SIMPLES (para testes) + tentativa automática de terminar processos suspeitos
Uso: python anti_ransomware.py [--dirs DIR1 DIR2 ...] [--scan-interval N]

AVISO:
- Esta ferramenta é para TESTES. Terminar processos pode causar perda de dados / instabilidade.
- Para terminar processos de outros usuários/serviços pode ser necessário rodar como root e ter psutil instalado.
"""

from pathlib import Path
import hashlib
import shutil
import time
import argparse
import threading
import sys
import os

# TENTA IMPORTAR PSUTIL (fallback gracioso)
try:
    import psutil
    PSUTIL_AVAILABLE = True
except Exception:
    psutil = None
    PSUTIL_AVAILABLE = False
    print("[WARN] psutil não encontrado. Função de terminar processos ficará desativada.")
    print("[INFO] Para ativar, instale via: sudo apt install python3-psutil  OR use virtualenv e pip install psutil")

# ---------- Configurações padrão ----------
DEFAULT_EXTS = {'.txt', '.docx', '.jpg', '.pdf', '.xlsx'}
SUSPECT_EXTS = {'.encrypted', '.lock', '.locked'}  # extensões que indicam "criptografado"
DEFAULT_SCAN_INTERVAL = 1.0  # segundos entre varreduras
MODIFICATION_THRESHOLD = 5   # número de arquivos modificados em WINDOW_SECONDS que aciona resposta
WINDOW_SECONDS = 8           # janela de tempo para contar modificações
BACKUP_FOLDER_NAME = ".backup_antiransom"
KILL_LOG_FILE = Path("/home/kali/Challenge/anti_ransom_kills.log")  # arquivo de log para kills

# ---------- Funções utilitárias ----------
def file_hash(path: Path):
    h = hashlib.sha256()
    try:
        with path.open('rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def ensure_backup_dir(base_dir: Path) -> Path:
    bdir = base_dir / BACKUP_FOLDER_NAME
    bdir.mkdir(parents=True, exist_ok=True)
    return bdir

def relative_backup_path(base_dir: Path, file_path: Path):
    # preserva estrutura relativa dentro do backup
    rel = file_path.relative_to(base_dir)
    return rel

def copy_to_backup(base_dir: Path, file_path: Path):
    bdir = ensure_backup_dir(base_dir)
    rel = relative_backup_path(base_dir, file_path)
    dest = bdir / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(file_path, dest)

def restore_from_backup(base_dir: Path, file_path: Path):
    bdir = base_dir / BACKUP_FOLDER_NAME
    rel = relative_backup_path(base_dir, file_path)
    src = bdir / rel
    if src.exists():
        dest_parent = file_path.parent
        dest_parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, file_path)
        return True
    return False

def restore_from_backup_by_original_name(base_dir: Path, suspected_encrypted_path: Path):
    """
    Tenta restaurar um arquivo renomeado para .encrypted
    Ex: arquivo.docx -> arquivo.docx.encrypted
    -> busca backup em .backup_antiransom/arquivo.docx
    """
    try:
        s = str(suspected_encrypted_path)
        if s.endswith('.encrypted'):
            orig_name = s[:-len('.encrypted')]
            orig_path = Path(orig_name)
            try:
                rel = orig_path.relative_to(base_dir)
                return restore_from_backup(base_dir, orig_path)
            except Exception:
                candidate = base_dir / orig_path.name
                if candidate.exists() and candidate.suffix in DEFAULT_EXTS:
                    return restore_from_backup(base_dir, candidate)
                else:
                    backup_candidate = base_dir / BACKUP_FOLDER_NAME / orig_path.name
                    if backup_candidate.exists():
                        target = base_dir / orig_path.name
                        target.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(backup_candidate, target)
                        return True
    except Exception:
        return False
    return False

# ---------- Funções para identificar e terminar processos ----------
def find_processes_using_path(target_path: Path):
    """
    Retorna lista de psutil.Process que possivelmente usam target_path.
    Verifica cmdline e arquivos abertos. Requer psutil.
    """
    procs = []
    if not PSUTIL_AVAILABLE:
        return procs

    target_str = str(target_path)
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            info = proc.info
            # checa cmdline (rápido)
            if info.get('cmdline'):
                if any(target_str in str(part) for part in info['cmdline']):
                    procs.append(proc)
                    continue
            # checa arquivos abertos
            try:
                for of in proc.open_files():
                    if target_str in of.path:
                        procs.append(proc)
                        break
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return procs

def append_kill_log(killed_entries):
    """
    killed_entries: lista de dicts com chaves: pid, name, cmdline (list), timestamp (iso)
    """
    try:
        with open(KILL_LOG_FILE, "a", encoding="utf-8") as f:
            for e in killed_entries:
                ts = e.get("timestamp")
                pid = e.get("pid")
                name = e.get("name")
                cmdline = " ".join(e.get("cmdline", [])) if e.get("cmdline") else ""
                f.write(f"{ts} - Processo morto: {name} (PID {pid}) CMD: {cmdline}\n")
    except Exception as exc:
        print(f"[ERROR] Falha ao escrever kill log: {exc}")

def attempt_kill_processes(procs, grace_seconds=2):
    """
    Retorna lista de dicts com info dos processos que foram finalizados
    """
    killed_info = []
    if not PSUTIL_AVAILABLE or not procs:
        return killed_info

    # deduplicate by pid
    unique = {}
    for p in procs:
        try:
            unique[p.pid] = p
        except Exception:
            continue
    procs = list(unique.values())

    proc_meta = {}
    for p in procs:
        try:
            cmd = []
            try:
                cmd = p.cmdline()
            except Exception:
                cmd = []
            proc_meta[p.pid] = {'proc': p, 'name': getattr(p, 'name', lambda: 'unknown')() if callable(getattr(p, 'name', None)) else getattr(p, 'name', 'unknown'), 'cmdline': cmd}
        except Exception:
            continue

    # envia terminate
    for p in procs:
        try:
            print(f"[ACTION] Enviando terminate() para PID {p.pid} ({p.name()})")
            p.terminate()
        except Exception as e:
            print(f"[WARN] Falha ao enviar terminate para PID {getattr(p, 'pid', None)}: {e}")

    try:
        gone, alive = psutil.wait_procs(procs, timeout=grace_seconds)
    except Exception:
        gone = procs
        alive = []

    # registra gone
    for p in gone:
        try:
            meta = proc_meta.get(p.pid, {})
            killed_info.append({
                'pid': p.pid,
                'name': meta.get('name', getattr(p, 'name', lambda: 'unknown')()),
                'cmdline': meta.get('cmdline', []),
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
            })
        except Exception:
            continue

    # força kill nos que não morreram
    for p in alive:
        try:
            print(f"[ACTION] PID {p.pid} não morreu; enviando kill()")
            p.kill()
            meta = proc_meta.get(p.pid, {})
            killed_info.append({
                'pid': p.pid,
                'name': meta.get('name', getattr(p, 'name', lambda: 'unknown')()),
                'cmdline': meta.get('cmdline', []),
                'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
            })
        except Exception as e:
            print(f"[ERROR] Falha ao forçar kill PID {getattr(p, 'pid', None)}: {e}")

    # dedupe killed_info por pid
    seen = set()
    unique_killed = []
    for k in killed_info:
        if k['pid'] not in seen:
            unique_killed.append(k)
            seen.add(k['pid'])

    # registra no log
    if unique_killed:
        append_kill_log(unique_killed)

    return unique_killed

# ---------- Monitor principal ----------
class AntiRansomMonitor:
    def __init__(self, directories, exts=DEFAULT_EXTS, interval=DEFAULT_SCAN_INTERVAL):
        self.directories = [Path(d).expanduser().resolve() for d in directories]
        self.exts = set(exts)
        self.interval = max(0.2, float(interval))
        self.running = False

        # metadata: { base_dir: { str(path) : {'hash':..., 'mtime':...} } }
        self.metadata = {}
        # event timestamps for detection (list of float timestamps)
        self.event_times = []
        # lock para segurança de threads
        self.lock = threading.Lock()

    def initialize(self):
        for base in self.directories:
            self.metadata[str(base)] = {}
            if not base.exists():
                print(f"[WARN] Diretório não existe: {base}. Será ignorado.")
                continue
            # garante pasta de backup
            ensure_backup_dir(base)
            # escaneia e cria backups iniciais
            print(f"[INFO] Inicializando varredura inicial em: {base}")
            for p in base.glob('**/*'):
                if p.is_file() and p.suffix in self.exts:
                    h = file_hash(p)
                    if h is not None:
                        self.metadata[str(base)][str(p)] = {'hash': h, 'mtime': p.stat().st_mtime}
                        # cria backup inicial se não existir
                        bpath = base / BACKUP_FOLDER_NAME / p.relative_to(base)
                        if not bpath.exists():
                            copy_to_backup(base, p)
            print(f"[INFO] Inicialização concluída para: {base} (arquivos monitorados: {len(self.metadata[str(base)])})")

    def scan_once(self):
        now = time.time()
        detections = []
        for base in self.directories:
            b = Path(base)
            if not b.exists():
                continue
            tracked = self.metadata.get(str(b), {})
            current_files = {}

            # varre arquivos alvo
            for p in b.glob('**/*'):
                if p.is_file() and p.suffix in self.exts.union(SUSPECT_EXTS):
                    current_files[str(p)] = {'path': p, 'mtime': p.stat().st_mtime, 'suffix': p.suffix}

            # check for modified/new/renamed files
            for fp_str, info in current_files.items():
                p = info['path']
                suffix = info['suffix']

                prev = tracked.get(fp_str)
                h = file_hash(p)
                if prev is None:
                    # arquivo novo (pode ser criado por processo legítimo)
                    tracked[fp_str] = {'hash': h, 'mtime': info['mtime']}
                    # cria backup do novo arquivo
                    try:
                        copy_to_backup(b, p)
                    except Exception as e:
                        print(f"[WARN] Não foi possível copiar backup de {p}: {e}")
                    continue

                # se hash mudou -> modificado
                if h is not None and h != prev.get('hash'):
                    # registra evento
                    detections.append({'type': 'modified', 'path': p, 'base': b, 'time': now})
                    # atualiza metadados (backup antes de sobrescrever já ocorreu em initialize; garantimos backup incremental)
                    try:
                        copy_to_backup(b, p)
                        tracked[fp_str] = {'hash': h, 'mtime': info['mtime']}
                    except Exception:
                        # mesmo sem backup, atualiza metadados para evitar repetição infinita
                        tracked[fp_str] = {'hash': h, 'mtime': info['mtime']}

                # se extensão suspeita (por exemplo, .encrypted), registra
                if suffix in SUSPECT_EXTS:
                    detections.append({'type': 'suspect_ext', 'path': p, 'base': b, 'time': now})

            # check for removed files (possible rename to .encrypted)
            removed = set(tracked.keys()) - set(current_files.keys())
            for removed_fp in removed:
                original_path = Path(removed_fp)
                candidate = original_path.with_suffix(original_path.suffix + '.encrypted')
                if candidate.exists():
                    detections.append({'type': 'renamed_to_encrypted', 'original': original_path, 'renamed': candidate, 'base': b, 'time': now})

            # store back
            self.metadata[str(b)] = tracked

        # process detections
        if detections:
            self.register_events(detections)

    def register_events(self, detections):
        now = time.time()
        with self.lock:
            # add timestamps for rate-based detection
            for d in detections:
                self.event_times.append(now)
            # prune old events
            cutoff = now - WINDOW_SECONDS
            self.event_times = [t for t in self.event_times if t >= cutoff]

            # log detections
            for d in detections:
                ttype = d.get('type')
                if ttype == 'modified':
                    print(f"[DETECT] Modificação detectada: {d['path']}")
                elif ttype == 'suspect_ext':
                    print(f"[DETECT] Extensão suspeita detectada: {d['path']}")
                elif ttype == 'renamed_to_encrypted':
                    print(f"[DETECT] Arquivo renomeado para .encrypted: {d.get('renamed')} (original: {d.get('original')})")
                else:
                    print(f"[DETECT] Evento: {d}")

            # se várias alterações em janela curta -> reação
            if len(self.event_times) >= MODIFICATION_THRESHOLD:
                print(f"\n[ALERTA] {len(self.event_times)} eventos em {WINDOW_SECONDS}s. Iniciando procedimento de contenção/restauração.\n")

                # 1) identificar processos candidatos relacionados aos arquivos detectados
                candidate_procs = []
                for d in detections:
                    if d.get('type') in ('suspect_ext', 'renamed_to_encrypted', 'modified'):
                        ppath = d.get('path') or d.get('renamed') or d.get('original')
                        if not ppath:
                            continue
                        ppath = Path(ppath)
                        # procura processos que tenham esse arquivo aberto ou referenciado
                        if PSUTIL_AVAILABLE:
                            procs = find_processes_using_path(ppath)
                            if procs:
                                print(f"[INFO] Processos potenciais que usam {ppath}: {', '.join(str(p.pid)+':'+p.name() for p in procs)}")
                            candidate_procs.extend(procs)
                        else:
                            print("[INFO] psutil não disponível — não posso identificar processos associados.")

                # 2) se houver candidatos e psutil disponível, tenta terminar
                if PSUTIL_AVAILABLE and candidate_procs:
                    # exige root para matar alguns processos; damos aviso se não for root
                    if os.geteuid() != 0:
                        print("[WARN] Você não está executando como root. Alguns processos podem não ser termináveis por falta de permissão.")
                    killed = attempt_kill_processes(candidate_procs, grace_seconds=2)
                    if killed:
                        print(f"[ACTION] Processos terminados: {[k['pid'] for k in killed]}")
                    else:
                        print("[ACTION] Nenhum processo finalizado (ou falha ao finalizar).")

                # 3) tentar restaurar arquivos afetados a partir do backup
                self.attempt_restore_recent()

                # 4) limpa eventos
                self.event_times.clear()

    def attempt_restore_recent(self):
        # Restaurar arquivos que possuem backup
        restored = 0
        for base in self.directories:
            b = Path(base)
            tracked = self.metadata.get(str(b), {})
            for fp_str, meta in list(tracked.items()):
                p = Path(fp_str)
                bpath = b / BACKUP_FOLDER_NAME / p.relative_to(b)
                try:
                    if p.exists():
                        if p.suffix in SUSPECT_EXTS:
                            # tenta restaurar buscando pelo nome original
                            if restore_from_backup_by_original_name(b, p):
                                restored += 1
                                print(f"[RESTORE] Restaurado (by original name) {p}")
                        else:
                            # compara hash com backup hash
                            if bpath.exists():
                                curr_hash = file_hash(p)
                                backup_hash = file_hash(bpath)
                                if backup_hash and curr_hash and curr_hash != backup_hash:
                                    if restore_from_backup(b, p):
                                        restored += 1
                                        print(f"[RESTORE] Restaurado {p} a partir do backup.")
                    else:
                        # arquivo removido - se houver backup, pode restaurar
                        if bpath.exists():
                            if restore_from_backup(b, p):
                                restored += 1
                                print(f"[RESTORE] Arquivo removido restaurado: {p}")
                except Exception as e:
                    print(f"[ERROR] Erro ao tentar restaurar {p}: {e}")

        print(f"[INFO] Processo de restauração automático finalizado. Restaurados: {restored}")

# ---------- Execução ----------
def parse_args():
    p = argparse.ArgumentParser(description="Anti-Ransomware simples (apenas para testes).")
    p.add_argument('--dirs', nargs='*', help='Diretórios para monitorar (padrão: Documents, Downloads, Pictures).', default=None)
    p.add_argument('--scan-interval', type=float, default=DEFAULT_SCAN_INTERVAL, help='Intervalo de varredura em segundos.')
    return p.parse_args()

def main():
    args = parse_args()
    if args.dirs:
        dirs = args.dirs
    else:
        home = Path.home()
        dirs = [str(home / "Documents"), str(home / "Downloads"), str(home / "Pictures")]

    print("Anti-Ransomware (teste) - monitorando:")
    for d in dirs:
        print(" -", d)

    monitor = AntiRansomMonitor(dirs, exts=DEFAULT_EXTS, interval=args.scan_interval)
    monitor.initialize()

    print("\n[RUNNING] Pressione Ctrl+C para sair. Logs aparecerão aqui.\n")
    try:
        monitor.running = True
        while True:
            monitor.scan_once()
            time.sleep(monitor.interval)
    except KeyboardInterrupt:
        print("\n[SHUTDOWN] Encerrando monitor. Deseja tentar restaurar tudo a partir dos backups? (s/n): ", end='')
        try:
            c = input().strip().lower()
            if c == 's':
                print("[ACTION] Tentando restaurar a partir de backups...")
                # restaura tudo contido em backups
                for base in monitor.directories:
                    b = Path(base)
                    bdir = b / BACKUP_FOLDER_NAME
                    if not bdir.exists():
                        continue
                    for fb in bdir.rglob('*'):
                        if fb.is_file():
                            # reconstruct destination
                            rel = fb.relative_to(bdir)
                            dest = b / rel
                            dest.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(fb, dest)
                print("[DONE] Restauração a partir dos backups concluída.")
            else:
                print("[NOTICE] Saindo sem restaurar. Backups persistem em cada pasta .backup_antiransom.")
        except Exception as e:
            print("[ERROR] Durante fechamento:", e)

if __name__ == "__main__":
    main()