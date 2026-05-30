use crate::encoding::put_bytes;
use crate::types::{ReceiverPublicKey, RevocationEntry, Tag};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Default)]
pub struct MerkleRevocationList {
    entries: Vec<RevocationEntry>,
    root: [u8; 32],
}

impl MerkleRevocationList {
    /// Tao Merkle revocation list rong.
    pub fn new() -> Self {
        let root = Sha256::digest(b"NIBSR/MERKLE/EMPTY/v1").into();
        Self { entries: Vec::new(), root }
    }

    /// Them entry vao danh sach va cap nhat Merkle root.
    pub fn add(&mut self, entry: RevocationEntry) {
        if !self.entries.iter().any(|x| x == &entry) {
            self.entries.push(entry);
            self.recompute_root();
        }
    }

    /// Xoa entry khoi danh sach va cap nhat Merkle root.
    pub fn remove(&mut self, entry: &RevocationEntry) {
        self.entries.retain(|x| x != entry);
        self.recompute_root();
    }

    /// Kiem tra cap (id, tau) co thuoc danh sach thu hoi hay khong.
    pub fn verify_tag(&self, id: &ReceiverPublicKey, tau: &Tag, scope: &str, now: u64) -> bool {
        self.entries
            .iter()
            .any(|x| &x.id == id && &x.tau == tau && x.covers(scope, now))
    }

    /// Cat bo entry het hieu luc va cap nhat root.
    pub fn prune(&mut self, now: u64) {
        self.entries.retain(|x| x.not_after >= now);
        self.recompute_root();
    }

    /// Cong bo digest (Merkle root) hien tai.
    pub fn publish_digest(&self) -> [u8; 32] {
        self.root
    }

    /// Tra ve Merkle root hien tai.
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    /// Tinh lai Merkle root tu toan bo entries.
    fn recompute_root(&mut self) {
        self.root = merkle_root(&self.entries);
    }
}

/// Tinh Merkle root tu danh sach entries.
fn merkle_root(entries: &[RevocationEntry]) -> [u8; 32] {
    if entries.is_empty() {
        return Sha256::digest(b"NIBSR/MERKLE/EMPTY/v1").into();
    }

    let mut leaves: Vec<[u8; 32]> = entries.iter().map(leaf_hash).collect();
    leaves.sort();

    while leaves.len() > 1 {
        let mut next = Vec::with_capacity((leaves.len() + 1) / 2);
        for pair in leaves.chunks(2) {
            let left = pair[0];
            let right = if pair.len() == 2 { pair[1] } else { pair[0] };
            next.push(node_hash(left, right));
        }
        leaves = next;
    }

    leaves[0]
}

/// Bam mot entry thanh hash la.
fn leaf_hash(entry: &RevocationEntry) -> [u8; 32] {
    let key = entry.lookup_key();
    let mut payload = Vec::new();
    payload.extend_from_slice(b"NIBSR/MERKLE/LEAF/v1");
    put_bytes(&mut payload, &key);
    Sha256::digest(payload).into()
}

/// Bam hai nut con thanh nut cha trong Merkle tree.
fn node_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"NIBSR/MERKLE/NODE/v1");
    h.update(left);
    h.update(right);
    h.finalize().into()
}
