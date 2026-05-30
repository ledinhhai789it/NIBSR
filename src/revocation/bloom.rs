use crate::encoding::{put_bytes, put_domain};
use crate::types::{ReceiverPublicKey, RevocationEntry, Tag};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct BloomRevocationList {
    bits: Vec<u8>,
    m_bits: usize,
    k_hashes: u32,
    /// Kept for pruning and rebuild. Verification remains Bloom-filter-based.
    entries: Vec<RevocationEntry>,
}

impl BloomRevocationList {
    /// Tao Bloom revocation list voi so bit va so ham bam cho truoc.
    pub fn new(m_bits: usize, k_hashes: u32) -> Self {
        let bytes = (m_bits + 7) / 8;
        Self {
            bits: vec![0; bytes],
            m_bits,
            k_hashes,
            entries: Vec::new(),
        }
    }

    /// Them entry vao Bloom filter va luu de co the rebuild khi can.
    pub fn add(&mut self, entry: RevocationEntry) {
        let key = entry.lookup_key();
        for i in 0..self.k_hashes {
            let pos = self.position(i, &key);
            self.set_bit(pos);
        }
        self.entries.push(entry);
    }

    /// Bloom filters cannot delete safely without counters; this rebuilds from
    /// the retained entries, which is adequate for the paper's optional Remove.
    /// Xoa entry bang cach rebuild Bloom filter tu danh sach con lai.
    pub fn remove(&mut self, entry: &RevocationEntry) {
        self.entries.retain(|x| x != entry);
        self.rebuild();
    }

    /// Conservative check: if all Bloom positions are set, the credential is
    /// treated as revoked. False positives are possible; false negatives are not.
    /// Kiem tra (id, tau) theo quy tac Bloom.
    pub fn verify_tag(&self, id: &ReceiverPublicKey, tau: &Tag, _scope: &str, _now: u64) -> bool {
        let key = lookup_key(id, tau);
        (0..self.k_hashes).all(|i| self.get_bit(self.position(i, &key)))
    }

    /// Cat bo entry het hieu luc va rebuild Bloom filter.
    pub fn prune(&mut self, now: u64) {
        self.entries.retain(|x| x.not_after >= now);
        self.rebuild();
    }

    /// Cong bo digest cua trang thai Bloom filter.
    pub fn publish_digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"NIBSR/BLOOM-DIGEST/v1");
        h.update((self.m_bits as u64).to_be_bytes());
        h.update(self.k_hashes.to_be_bytes());
        h.update(&self.bits);
        h.finalize().into()
    }

    /// Dem so bit dang duoc bat trong Bloom filter.
    pub fn bit_count(&self) -> usize {
        self.bits.iter().map(|b| b.count_ones() as usize).sum()
    }

    /// Xay lai toan bo bitset tu danh sach entries hien tai.
    fn rebuild(&mut self) {
        self.bits.fill(0);
        let entries = self.entries.clone();
        for entry in entries {
            let key = entry.lookup_key();
            for i in 0..self.k_hashes {
                let pos = self.position(i, &key);
                self.set_bit(pos);
            }
        }
    }

    /// Tinh vi tri bit cho lan bam thu i.
    fn position(&self, i: u32, key: &[u8]) -> usize {
        let mut h = Sha256::new();
        h.update(b"NIBSR/BLOOM-POS/v1");
        h.update(i.to_be_bytes());
        h.update(key);
        let digest: [u8; 32] = h.finalize().into();
        let mut first_8 = [0u8; 8];
        first_8.copy_from_slice(&digest[..8]);
        (u64::from_be_bytes(first_8) as usize) % self.m_bits.max(1)
    }

    /// Bat bit tai vi tri cho truoc.
    fn set_bit(&mut self, pos: usize) {
        let byte = pos / 8;
        let bit = pos % 8;
        self.bits[byte] |= 1u8 << bit;
    }

    /// Doc bit tai vi tri cho truoc.
    fn get_bit(&self, pos: usize) -> bool {
        let byte = pos / 8;
        let bit = pos % 8;
        (self.bits[byte] & (1u8 << bit)) != 0
    }
}

/// Tao khoa lookup tu (id, tau) cho Bloom filter.
fn lookup_key(id: &ReceiverPublicKey, tau: &Tag) -> Vec<u8> {
    let mut out = Vec::new();
    put_domain(&mut out, "NIBSR/REVOCATION-KEY/v1");
    put_bytes(&mut out, &id.0);
    put_bytes(&mut out, tau);
    out
}
