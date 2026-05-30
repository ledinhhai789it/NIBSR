use crate::types::{hash_revocation_entries, ReceiverPublicKey, RevocationEntry, Tag};

#[derive(Clone, Debug, Default)]
pub struct SetRevocationList {
    entries: Vec<RevocationEntry>,
}

impl SetRevocationList {
    /// Tao danh sach thu hoi kieu Set rong.
    pub fn new() -> Self {
        Self { entries: Vec::new() }
    }

    /// Them entry vao Set neu chua ton tai.
    pub fn add(&mut self, entry: RevocationEntry) {
        if !self.entries.iter().any(|x| x == &entry) {
            self.entries.push(entry);
        }
    }

    /// Xoa entry khoi Set.
    pub fn remove(&mut self, entry: &RevocationEntry) {
        self.entries.retain(|x| x != entry);
    }

    /// Kiem tra cap (id, tau) co thuoc danh sach thu hoi hay khong.
    pub fn verify_tag(&self, id: &ReceiverPublicKey, tau: &Tag, scope: &str, now: u64) -> bool {
        self.entries
            .iter()
            .any(|x| &x.id == id && &x.tau == tau && x.covers(scope, now))
    }

    /// Cat bo cac entry da het hieu luc.
    pub fn prune(&mut self, now: u64) {
        self.entries.retain(|x| x.not_after >= now);
    }

    /// Cong bo digest cua Set hien tai.
    pub fn publish_digest(&self) -> [u8; 32] {
        hash_revocation_entries(&self.entries)
    }

    /// Tra ve danh sach entry hien co.
    pub fn entries(&self) -> &[RevocationEntry] {
        &self.entries
    }
}
