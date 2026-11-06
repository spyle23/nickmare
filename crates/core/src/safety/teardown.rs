//! Teardown garanti (issue #26, cf. `docs/ARCHITECTURE.md` §11.1).
//!
//! Toute ressource ouverte (sessions, sockets, sessions Metasploit, fichiers
//! temporaires contenant des hashes) doit être **libérée via RAII/`Drop`**,
//! même en cas de panique ou d'interruption (`Ctrl-C` capté → arrêt propre).
//!
//! Ce module fournit :
//!
//! - [`ShutdownFlag`] : drapeau d'arrêt **coopératif** partagé. Le gestionnaire
//!   de signal (SIGINT/Ctrl-C), côté binaire, se contente de le lever ; la
//!   boucle d'orchestration le consulte et sort proprement, ce qui déclenche les
//!   `Drop`. Le drapeau est injectable en test (on le lève à la main), sans
//!   dépendre d'un vrai signal OS.
//! - [`TeardownGuard`] : garde RAII qui **libère ses ressources en ordre inverse**
//!   d'acquisition dès qu'elle sort du périmètre — y compris lors d'un déroulement
//!   de pile (`panic`) — en les consignant dans un registre observable.
//! - [`TempFile`] : fichier temporaire **effacé au `Drop`** (les hashes capturés
//!   ne traînent jamais sur le disque après l'arrêt).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Drapeau d'arrêt coopératif partagé entre le gestionnaire de signal et la
/// boucle d'orchestration. Clonable : toutes les copies partagent le même état.
#[derive(Debug, Clone, Default)]
pub struct ShutdownFlag {
    requested: Arc<AtomicBool>,
}

impl ShutdownFlag {
    /// Nouveau drapeau, arrêt non demandé.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Demande l'arrêt (appelé par le gestionnaire de signal).
    pub fn request(&self) {
        self.requested.store(true, Ordering::SeqCst);
    }

    /// Vrai si un arrêt a été demandé : la boucle doit sortir proprement.
    #[must_use]
    pub fn is_requested(&self) -> bool {
        self.requested.load(Ordering::SeqCst)
    }
}

/// Nature d'une ressource suivie par un [`TeardownGuard`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    /// Session applicative (ex. session Metasploit).
    Session,
    /// Socket réseau.
    Socket,
    /// Fichier temporaire (ex. hashes capturés).
    TempFile,
    /// Autre ressource à libérer.
    Other,
}

impl ResourceKind {
    /// Libellé court de la nature de la ressource.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            ResourceKind::Session => "session",
            ResourceKind::Socket => "socket",
            ResourceKind::TempFile => "fichier-temp",
            ResourceKind::Other => "ressource",
        }
    }
}

/// Garde RAII : libère toutes les ressources enregistrées dès qu'elle est
/// `Drop`ée (fin de portée, retour anticipé, ou panique), en **ordre inverse**
/// d'enregistrement. La libération est consignée dans un registre partagé, ce
/// qui la rend observable en test.
#[derive(Debug, Default)]
pub struct TeardownGuard {
    resources: Vec<(String, ResourceKind)>,
    ledger: Arc<Mutex<Vec<String>>>,
    done: bool,
}

impl TeardownGuard {
    /// Garde neuve avec son propre registre.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Garde neuve branchée sur un registre **externe** partagé : permet
    /// d'observer la libération après que la garde a disparu (notamment lors
    /// d'une panique, où le registre interne serait inaccessible).
    #[must_use]
    pub fn with_ledger(ledger: Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            resources: Vec::new(),
            ledger,
            done: false,
        }
    }

    /// Enregistre une ressource à libérer (dans l'ordre d'acquisition).
    pub fn register(&mut self, name: impl Into<String>, kind: ResourceKind) {
        self.resources.push((name.into(), kind));
    }

    /// Handle clonable vers le registre de libération, pour l'observer après que
    /// la garde a été `Drop`ée.
    #[must_use]
    pub fn ledger(&self) -> Arc<Mutex<Vec<String>>> {
        Arc::clone(&self.ledger)
    }

    /// Libère explicitement maintenant (idempotent : le `Drop` ne refera rien).
    pub fn release(&mut self) {
        self.teardown();
    }

    /// Nombre de ressources encore à libérer.
    #[must_use]
    pub fn pending(&self) -> usize {
        self.resources.len()
    }

    fn teardown(&mut self) {
        if self.done {
            return;
        }
        self.done = true;
        if let Ok(mut log) = self.ledger.lock() {
            // Ordre inverse d'acquisition (LIFO), comme une pile de ressources.
            while let Some((name, kind)) = self.resources.pop() {
                log.push(format!("libéré {} {name}", kind.label()));
            }
        } else {
            // Registre empoisonné : on vide quand même pour ne rien laisser ouvert.
            self.resources.clear();
        }
    }
}

impl Drop for TeardownGuard {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// Fichier temporaire supprimé automatiquement au `Drop` : garantit qu'aucune
/// donnée sensible capturée (hashes…) ne subsiste après l'arrêt.
#[derive(Debug)]
pub struct TempFile {
    path: PathBuf,
}

impl TempFile {
    /// Crée un fichier temporaire vide au chemin donné.
    pub fn create(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        fs::File::create(&path)?;
        Ok(Self { path })
    }

    /// Crée un fichier temporaire contenant `contents`.
    pub fn create_with(path: impl Into<PathBuf>, contents: &[u8]) -> io::Result<Self> {
        let path = path.into();
        fs::write(&path, contents)?;
        Ok(Self { path })
    }

    /// Chemin du fichier.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        // Best-effort : à l'arrêt, on efface sans propager d'erreur.
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn drapeau_partage_entre_copies() {
        let flag = ShutdownFlag::new();
        let copie = flag.clone();
        assert!(!flag.is_requested());
        copie.request(); // le « gestionnaire de signal » lève le drapeau
        assert!(flag.is_requested(), "toutes les copies partagent l'état");
    }

    #[test]
    fn la_garde_libere_en_ordre_inverse_a_la_sortie_de_portee() {
        let ledger = {
            let mut guard = TeardownGuard::new();
            guard.register("msf-1", ResourceKind::Session);
            guard.register("tcp:4444", ResourceKind::Socket);
            guard.register("/tmp/hashes", ResourceKind::TempFile);
            let handle = guard.ledger();
            assert_eq!(guard.pending(), 3);
            handle
            // `guard` est Drop ici → teardown.
        };
        let released = ledger.lock().unwrap();
        assert_eq!(released.len(), 3);
        // LIFO : le fichier temp (acquis en dernier) est libéré en premier.
        assert_eq!(released[0], "libéré fichier-temp /tmp/hashes");
        assert_eq!(released[1], "libéré socket tcp:4444");
        assert_eq!(released[2], "libéré session msf-1");
    }

    #[test]
    fn la_garde_libere_meme_en_cas_de_panique() {
        // Registre externe observable après la panique (le registre interne
        // serait, lui, inaccessible une fois la garde `Drop`ée).
        let ledger = Arc::new(Mutex::new(Vec::new()));
        let guard_ledger = Arc::clone(&ledger);
        let result = catch_unwind(AssertUnwindSafe(move || {
            let mut guard = TeardownGuard::with_ledger(guard_ledger);
            guard.register("session-x", ResourceKind::Session);
            guard.register("socket-y", ResourceKind::Socket);
            panic!("interruption simulée en plein run");
        }));
        assert!(result.is_err(), "la panique est bien survenue");
        let released = ledger.lock().unwrap();
        assert_eq!(released.len(), 2, "tout est libéré malgré la panique");
        // LIFO respecté pendant le déroulement de pile.
        assert_eq!(released[0], "libéré socket socket-y");
        assert_eq!(released[1], "libéré session session-x");
    }

    #[test]
    fn libere_une_seule_fois_meme_apres_release_explicite() {
        let mut guard = TeardownGuard::new();
        guard.register("session-z", ResourceKind::Session);
        let handle = guard.ledger();
        guard.release();
        assert_eq!(handle.lock().unwrap().len(), 1);
        drop(guard); // le Drop ne doit pas re-libérer
        assert_eq!(handle.lock().unwrap().len(), 1, "libération idempotente");
    }

    #[test]
    fn fichier_temp_efface_au_drop() {
        let dir = std::env::temp_dir().join(format!("nm-teardown-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hashes.tmp");
        {
            let temp = TempFile::create_with(&path, b"ntlm:deadbeef").unwrap();
            assert!(
                temp.path().exists(),
                "le fichier temp existe pendant l'usage"
            );
        }
        assert!(!path.exists(), "le fichier temp est effacé au Drop");
    }
}
