//! Synthetic 2-of-3 shares for recovery tests. The secret is public test data;
//! f(x) = root + 11*x with x = 1, 2, 3. OT material is unused by recovery.

use k256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint, Scalar};
use sl_dkls23::keygen::Keyshare;

pub(crate) fn keyshare(root: u64, party_id: u8, extra: &[u8]) -> Vec<u8> {
    assert!(root > 0 && party_id < 3);
    let mut bytes = Keyshare::new(3, 2, party_id, extra).as_slice().to_vec();

    // Byte offsets from the pinned DKLS23 KeyshareInfo / EachParty layout.
    // Keyshare::new supplies the header, lengths and space for all parties.
    const CHAIN_CODE: usize = 43;
    const PUBLIC_KEY: usize = 75;
    const SECRET_SHARE: usize = 140;
    const HEADER_SIZE: usize = 172;
    const PARTY_SIZE: usize = 98;

    bytes[CHAIN_CODE..CHAIN_CODE + 32].fill(42);
    let public = (ProjectivePoint::GENERATOR * Scalar::from(root))
        .to_affine()
        .to_encoded_point(true);
    bytes[PUBLIC_KEY..PUBLIC_KEY + 33].copy_from_slice(public.as_bytes());
    let secret = Scalar::from(root) + Scalar::from(11 * (u64::from(party_id) + 1));
    bytes[SECRET_SHARE..SECRET_SHARE + 32].copy_from_slice(&secret.to_bytes());

    for i in 0..3 {
        let offset = HEADER_SIZE + PARTY_SIZE * i;
        let x = Scalar::from(i as u64 + 1);
        let s = Scalar::from(root) + Scalar::from(11u64) * x;
        let public_share = (ProjectivePoint::GENERATOR * s)
            .to_affine()
            .to_encoded_point(true);
        bytes[offset + 1..offset + 34].copy_from_slice(public_share.as_bytes());
        bytes[offset + 34..offset + 66].copy_from_slice(&x.to_bytes());
    }
    assert!(Keyshare::from_bytes(&bytes).is_some());
    bytes
}
