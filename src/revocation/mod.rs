mod bloom;
mod merkle;
mod set;

pub use bloom::BloomRevocationList;
pub use merkle::MerkleRevocationList;
pub use set::SetRevocationList;

use crate::types::{ReceiverPublicKey, RevocationEntry, Tag};

#[derive(Clone, Debug)]
pub enum RevocationList {
    Set(SetRevocationList),
    Bloom(BloomRevocationList),
    Merkle(MerkleRevocationList),
}

impl RevocationList {
    /// Khoi tao RevList dang SET theo ten mo ta trong tai lieu.
    #[allow(non_snake_case)]
    /// Tao RevList theo mode Set.
    pub fn Set() -> Self {
        Self::set()
    }

    /// Khoi tao RevList dang Bloom theo ten mo ta trong tai lieu.
    #[allow(non_snake_case)]
    /// Tao RevList theo mode Bloom.
    pub fn Bloom(m_bits: usize, k_hashes: u32) -> Self {
        Self::bloom(m_bits, k_hashes)
    }

    /// Khoi tao RevList dang Merkle theo ten mo ta trong tai lieu.
    #[allow(non_snake_case)]
    /// Tao RevList theo mode Merkle.
    pub fn Merkle() -> Self {
        Self::merkle()
    }

    /// Ham Add: them phan tu thu hoi vao danh sach.
    #[allow(non_snake_case)]
    /// Them entry vao RevList.
    pub fn Add(&mut self, entry: RevocationEntry) {
        self.add(entry);
    }

    /// Ham Remove: xoa phan tu thu hoi khoi danh sach.
    #[allow(non_snake_case)]
    /// Xoa entry khoi RevList.
    pub fn Remove(&mut self, entry: &RevocationEntry) {
        self.remove(entry);
    }

    /// Ham Prune: loai bo cac entry het hieu luc.
    #[allow(non_snake_case)]
    /// Cat bo entry het hieu luc trong RevList.
    pub fn Prune(&mut self, now: u64) {
        self.prune(now);
    }

    /// Ham PublishDigest: cong bo digest cua trang thai RevList.
    #[allow(non_snake_case)]
    /// Cong bo digest cua RevList.
    pub fn PublishDigest(&self) -> [u8; 32] {
        self.publish_digest()
    }

    /// Tao danh sach thu hoi dang Set.
    #[allow(non_snake_case)]
    pub fn TaoSet() -> Self {
        Self::set()
    }

    /// Tao danh sach thu hoi dang Bloom filter.
    #[allow(non_snake_case)]
    pub fn TaoBloom(m_bits: usize, k_hashes: u32) -> Self {
        Self::bloom(m_bits, k_hashes)
    }

    /// Tao danh sach thu hoi dang Merkle tree.
    #[allow(non_snake_case)]
    pub fn TaoMerkle() -> Self {
        Self::merkle()
    }

    /// Them mot entry vao danh sach thu hoi.
    #[allow(non_snake_case)]
    pub fn Them(&mut self, entry: RevocationEntry) {
        self.add(entry);
    }

    /// Xoa mot entry khoi danh sach thu hoi.
    #[allow(non_snake_case)]
    pub fn Xoa(&mut self, entry: &RevocationEntry) {
        self.remove(entry);
    }

    /// Kiem tra (id, tau) co bi thu hoi trong thoi diem va scope hien tai hay khong.
    #[allow(non_snake_case)]
    pub fn KiemTraThe(&self, id: &ReceiverPublicKey, tau: &Tag, scope: &str, now: u64) -> bool {
        self.verify_tag(id, tau, scope, now)
    }

    /// Tao RevList Set (ten snake_case).
    pub fn set() -> Self {
        Self::Set(SetRevocationList::new())
    }

    /// Tao RevList Bloom (ten snake_case).
    pub fn bloom(m_bits: usize, k_hashes: u32) -> Self {
        Self::Bloom(BloomRevocationList::new(m_bits, k_hashes))
    }

    /// Tao RevList Merkle (ten snake_case).
    pub fn merkle() -> Self {
        Self::Merkle(MerkleRevocationList::new())
    }

    /// Them entry vao RevList theo mode hien tai.
    pub fn add(&mut self, entry: RevocationEntry) {
        match self {
            Self::Set(list) => list.add(entry),
            Self::Bloom(list) => list.add(entry),
            Self::Merkle(list) => list.add(entry),
        }
    }

    /// Xoa entry khoi RevList theo mode hien tai.
    pub fn remove(&mut self, entry: &RevocationEntry) {
        match self {
            Self::Set(list) => list.remove(entry),
            Self::Bloom(list) => list.remove(entry),
            Self::Merkle(list) => list.remove(entry),
        }
    }

    /// Kiem tra cap (id, tau) tren RevList theo mode hien tai.
    pub fn verify_tag(&self, id: &ReceiverPublicKey, tau: &Tag, scope: &str, now: u64) -> bool {
        match self {
            Self::Set(list) => list.verify_tag(id, tau, scope, now),
            Self::Bloom(list) => list.verify_tag(id, tau, scope, now),
            Self::Merkle(list) => list.verify_tag(id, tau, scope, now),
        }
    }

    /// Cat bo entry het hieu luc theo mode hien tai.
    pub fn prune(&mut self, now: u64) {
        match self {
            Self::Set(list) => list.prune(now),
            Self::Bloom(list) => list.prune(now),
            Self::Merkle(list) => list.prune(now),
        }
    }

    /// Lay digest theo mode hien tai.
    pub fn publish_digest(&self) -> [u8; 32] {
        match self {
            Self::Set(list) => list.publish_digest(),
            Self::Bloom(list) => list.publish_digest(),
            Self::Merkle(list) => list.publish_digest(),
        }
    }
}
