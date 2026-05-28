// Licensed under the Apache-2.0 license
//
// Taken from https://github.com/OpenPRoT/openprot

#![no_std]

//! Implementations of the platform abstractions needed for SPDM

mod cert_chain;

use cert_chain::*;

use embassy_stm32::rng::{Instance, Rng};
use heapless::Vec;
use p384::ecdsa::signature::SignerMut;
use p384::ecdsa::{Signature, SigningKey};
use pkcs8::PrivateKeyInfo;
use spdm_lib::cert_store::{CertStoreError, CertStoreResult, PeerCertStore, SpdmCertStore};
use spdm_lib::commands::challenge::MeasurementSummaryHashType;
use spdm_lib::platform::evidence::{SpdmEvidence, SpdmEvidenceError, SpdmEvidenceResult};
use spdm_lib::platform::hash::{SpdmHash, SpdmHashAlgoType, SpdmHashError, SpdmHashResult};
use spdm_lib::platform::rng::{SpdmRng, SpdmRngResult};
use spdm_lib::protocol::algorithms::{AsymAlgo, ECC_P384_SIGNATURE_SIZE, SHA384_HASH_SIZE};
use spdm_lib::protocol::certs::{CertificateInfo, KeyUsageMask};
use spdm_lib::protocol::{
    AeadCipherSuite, AlgorithmPriorityTable, BaseAsymAlgo, BaseHashAlgo, BaseHashAlgoType,
    DeviceAlgorithms, DheNamedGroup, KeySchedule, LocalDeviceAlgorithms, MeasurementHashAlgo,
    MeasurementSpecification, MelSpecification, OtherParamSupport, ReqBaseAsymAlg,
    SpdmCertChainHeader,
};
use zerocopy::FromBytes;

use defmt::error;

/// Mock certificate store with fixed placeholder data
pub struct MockCertStore;

impl MockCertStore {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MockCertStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SpdmCertStore for MockCertStore {
    fn slot_count(&self) -> u8 {
        1
    }

    fn is_provisioned(&self, slot_id: u8) -> bool {
        slot_id == 0
    }

    fn cert_chain_len(&mut self, asym_algo: AsymAlgo, slot_id: u8) -> CertStoreResult<usize> {
        if slot_id != 0 {
            return Err(CertStoreError::InvalidSlotId(slot_id));
        }
        if asym_algo != AsymAlgo::EccP384 {
            return Err(CertStoreError::UnsupportedHashAlgo);
        }
        Ok(CERT_CHAIN_LEN)
    }

    fn get_cert_chain(
        &mut self,
        slot_id: u8,
        asym_algo: AsymAlgo,
        offset: usize,
        cert_portion: &mut [u8],
    ) -> CertStoreResult<usize> {
        if slot_id != 0 {
            return Err(CertStoreError::InvalidSlotId(slot_id));
        }
        if asym_algo != AsymAlgo::EccP384 {
            return Err(CertStoreError::UnsupportedHashAlgo);
        }

        let cert_chain_len = self.cert_chain_len(asym_algo, slot_id)?;
        if offset >= cert_chain_len {
            return Err(CertStoreError::InvalidOffset);
        }

        let remaining = cert_chain_len - offset;
        let to_copy = remaining.min(cert_portion.len());
        let portion = &mut cert_portion[..to_copy];

        // Create an iterator that yields the bytes we need
        let cert_chain_iter = [CA_CERT, INTER_CERT, END_RESPONDER_CERT]
            .iter()
            .flat_map(|e| e.iter())
            .skip(offset)
            .take(to_copy);

        for (n, x) in cert_chain_iter.enumerate() {
            portion[n] = *x;
        }

        // Fill remaining with zeros if any
        if to_copy < cert_portion.len() {
            cert_portion[to_copy..].fill(0);
        }

        Ok(to_copy)
    }

    fn root_cert_hash(
        &mut self,
        slot_id: u8,
        asym_algo: AsymAlgo,
        cert_hash: &mut [u8; SHA384_HASH_SIZE],
    ) -> CertStoreResult<()> {
        if slot_id != 0 {
            return Err(CertStoreError::InvalidSlotId(slot_id));
        }
        if asym_algo != AsymAlgo::EccP384 {
            return Err(CertStoreError::UnsupportedHashAlgo);
        }

        for i in 0..SHA384_HASH_SIZE {
            cert_hash[i] = u8::from_str_radix(&HEX_CA_CERT_SHA384[i * 2..i * 2 + 2], 16).unwrap();
        }
        Ok(())
    }

    fn sign_hash(
        &self,
        slot_id: u8,
        hash: &[u8; SHA384_HASH_SIZE],
        signature: &mut [u8; ECC_P384_SIGNATURE_SIZE],
    ) -> CertStoreResult<()> {
        if slot_id != 0 {
            return Err(CertStoreError::InvalidSlotId(slot_id));
        }

        let key_info = PrivateKeyInfo::try_from(END_RESPONDER_KEY).unwrap();
        let mut key = SigningKey::try_from(key_info).unwrap();

        let sig: Signature = key.sign(hash);
        let sig_bytes = sig.to_bytes();
        assert_eq!(sig_bytes.len(), ECC_P384_SIGNATURE_SIZE);

        signature.copy_from_slice(&sig_bytes);

        Ok(())
    }

    fn key_pair_id(&self, _slot_id: u8) -> Option<u8> {
        None
    }

    fn cert_info(&self, _slot_id: u8) -> Option<CertificateInfo> {
        None
    }

    fn key_usage_mask(&self, _slot_id: u8) -> Option<KeyUsageMask> {
        None
    }
}

/// Mock hash implementation
pub struct MockHash {
    buffer: [u8; 96],
    pos: usize,
    algo: Option<SpdmHashAlgoType>,
}

impl MockHash {
    pub fn new() -> Self {
        Self {
            buffer: [0u8; 96],
            pos: 0,
            algo: None,
        }
    }
}

impl Default for MockHash {
    fn default() -> Self {
        Self::new()
    }
}

impl SpdmHash for MockHash {
    fn init(&mut self, algo: SpdmHashAlgoType, _secret: Option<&[u8]>) -> SpdmHashResult<()> {
        self.pos = 0;
        self.algo = Some(algo);
        Ok(())
    }

    fn update(&mut self, data: &[u8]) -> SpdmHashResult<()> {
        for (pos, x) in data.iter().enumerate() {
            self.buffer[pos % self.buffer.len()] = self.buffer[pos % self.buffer.len()] ^ x;
        }
        Ok(())
    }

    fn finalize(&mut self, dest: &mut [u8]) -> SpdmHashResult<()> {
        let hash_size = match self.algo {
            Some(SpdmHashAlgoType::SHA384) => 48,
            Some(SpdmHashAlgoType::SHA512) => 64,
            _ => return Err(SpdmHashError::InvalidAlgorithm),
        };

        if dest.len() < hash_size {
            return Err(SpdmHashError::BufferTooSmall);
        }

        dest[..hash_size].copy_from_slice(&self.buffer[..hash_size]);

        Ok(())
    }

    fn hash(&mut self, algo: SpdmHashAlgoType, data: &[u8], dest: &mut [u8]) -> SpdmHashResult<()> {
        self.init(algo, None)?;
        self.update(data)?;
        self.finalize(dest)
    }

    fn reset(&mut self) {
        self.pos = 0;
        self.algo = None;
    }

    fn algo(&self) -> SpdmHashAlgoType {
        self.algo.unwrap_or(SpdmHashAlgoType::SHA384)
    }
}

/// Mock RNG implementation
pub struct MockRng<T: Instance> {
    rng: Rng<'static, T>,
}

impl<T: Instance> MockRng<T> {
    pub fn new(rng: Rng<'static, T>) -> Self {
        Self { rng }
    }
}

impl<T: Instance> SpdmRng for MockRng<T> {
    fn get_random_bytes(&mut self, buf: &mut [u8]) -> SpdmRngResult<()> {
        // Mock: fill with incrementing pattern
        // for (i, byte) in buf.iter_mut().enumerate() {
        //     *byte = (i & 0xFF) as u8;
        // }
        self.rng.fill_bytes(buf);
        Ok(())
    }

    fn generate_random_number(&mut self, random_number: &mut [u8]) -> SpdmRngResult<()> {
        // Mock: fill with incrementing pattern starting from 0x42
        // for (i, byte) in random_number.iter_mut().enumerate() {
        //     *byte = ((i + 0x42) & 0xFF) as u8;
        // }
        self.rng.fill_bytes(random_number);
        Ok(())
    }
}

/// Mock evidence implementation
pub struct MockEvidence;

impl MockEvidence {
    pub fn new() -> Self {
        Self
    }
}

impl Default for MockEvidence {
    fn default() -> Self {
        Self::new()
    }
}

impl SpdmEvidence for MockEvidence {
    fn pcr_quote_size(&self, _with_pqc_sig: bool) -> SpdmEvidenceResult<usize> {
        // Mock: 2 measurements
        // Format: count(1) + [index(1) + size(2) + data]*2
        Ok(1 + (1 + 2 + 23) + (1 + 2 + 20))
    }

    fn pcr_quote(&self, dest: &mut [u8], _with_pqc_sig: bool) -> SpdmEvidenceResult<usize> {
        let required_size = self.pcr_quote_size(false)?;
        if dest.len() < required_size {
            return Err(SpdmEvidenceError::InvalidEvidenceFormat);
        }

        let mut offset = 0;

        // Measurement count
        dest[offset] = 2;
        offset += 1;

        // Measurement 0
        dest[offset] = 0; // index
        offset += 1;
        dest[offset..offset + 2].copy_from_slice(&23u16.to_le_bytes()); // size
        offset += 2;
        dest[offset..offset + 23].copy_from_slice(b"OpenPRoT SPDM Loopback");
        offset += 23;

        // Measurement 1
        dest[offset] = 1; // index
        offset += 1;
        dest[offset..offset + 2].copy_from_slice(&20u16.to_le_bytes()); // size
        offset += 2;
        dest[offset..offset + 20].copy_from_slice(b"MCTP Loopback Test  ");
        offset += 20;

        Ok(offset)
    }
}

#[derive(Debug, Default)]
pub struct PeerSlot {
    /// CertChain[K], retrieved in `CERTIFICATE` response.
    pub cert_chain: Vec<u8, 4096>,

    /// Digest[K], retrieved in `DIGESTS` response.
    pub digest: Vec<u8, 48>,

    /// `KeyPairID[K]`, retrieved in `DIGESTS` response if the corresponding `MULTI_KEY_CONN_REQ` or `MULTI_KEY_CONN_RSP` is true.
    pub keypair_id: Option<u8>,

    /// `CertificateInfo[K]`, retrieved in `DIGESTS` response if the corresponding `MULTI_KEY_CONN_REQ` or `MULTI_KEY_CONN_RSP` is true. pub cert_info: Option<CertificateInfo>
    pub certificate_info: Option<CertificateInfo>,

    /// KeyUsageMask[K], retrieved in `DIGESTS` response if the corresponding `MULTI_KEY_CONN_REQ` or `MULTI_KEY_CONN_RSP` is true.
    pub key_usage_mask: Option<KeyUsageMask>,

    pub requested_msh_type: Option<MeasurementSummaryHashType>,
}

impl PeerSlot {
    /// Get the digest for the root certificate of the chain
    ///
    /// # Arguments
    /// * `hash_algo` - The hash algorithm negotiated with the peer.
    fn get_root_hash(&self, hash_algo: BaseHashAlgoType) -> Option<&[u8]> {
        let (length, rest) = SpdmCertChainHeader::ref_from_prefix(&self.cert_chain).ok()?;
        if length.get_length() != self.cert_chain.len() as u32 {
            error!("cert chain length mismatch");
            return None;
        }
        Some(&rest[..hash_algo.hash_byte_size()])
    }
    /// Get the DER x509 certificate chain
    ///
    /// # Arguments
    /// * `hash_algo` - The hash algorithm negotiated with the peer.
    fn get_cert_chain(&self, hash_algo: BaseHashAlgoType) -> Option<&[u8]> {
        let (length, rest) = SpdmCertChainHeader::ref_from_prefix(&self.cert_chain).ok()?;
        if length.get_length() != self.cert_chain.len() as u32 {
            error!("cert chain length mismatch");
            return None;
        }
        Some(&rest[hash_algo.hash_byte_size()..])
    }
}

/// Concrete implementation of `PeerCertStore` for demonstration purposes.
/// This example store manages a single certificate slot (slot 0) and allows
/// setting and retrieving the certificate chain, digest, key pair ID, certificate info,
/// and key usage mask for that slot. In a real implementation, you would likely
/// want to support multiple slots and have more robust error handling and storage mechanisms.
#[derive(Debug)]
pub struct DemoPeerCertStore {
    /// Retrieved from `DIGESTS` response, indicates which certificate slots are supported by the peer.
    supported_slots_mask: u8,

    /// Retrieved from `DIGESTS` response, indicates which certificate slots are provisioned with valid certificate chains.
    provisioned_slots_mask: u8,

    // Since not all existing slots may hold eligible certificate chains, keep the PeerSlot values optional.
    pub peer_slots: Vec<Option<PeerSlot>, 1>,
}

impl Default for DemoPeerCertStore {
    fn default() -> Self {
        let mut slots = Vec::new();
        let _ = slots.push(None);
        DemoPeerCertStore {
            supported_slots_mask: 0,
            provisioned_slots_mask: 0,
            peer_slots: slots,
        }
    }
}

impl PeerCertStore for DemoPeerCertStore {
    fn slot_count(&self) -> u8 {
        self.peer_slots.len() as u8
    }

    fn assemble(
        &mut self,
        slot_id: u8,
        portion: &[u8],
    ) -> Result<spdm_lib::cert_store::ReassemblyStatus, CertStoreError> {
        let slot = self
            .peer_slots
            .get_mut(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_mut()
            .ok_or(CertStoreError::PlatformError)?;

        slot.cert_chain
            .extend_from_slice(portion)
            .map_err(|_| CertStoreError::BufferTooSmall)?;

        Ok(spdm_lib::cert_store::ReassemblyStatus::InProgress)
    }

    fn reset(&mut self, slot_id: u8) {
        if let Some(Some(slot)) = self.peer_slots.get_mut(slot_id as usize) {
            *slot = PeerSlot::default();
        }
    }

    fn get_raw_chain(&self, slot_id: u8) -> CertStoreResult<&[u8]> {
        let slot = self
            .peer_slots
            .get(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_ref()
            .ok_or(CertStoreError::PlatformError)?;
        Ok(&slot.cert_chain)
    }

    fn get_cert_chain(&self, slot_id: u8, hash_algo: BaseHashAlgoType) -> CertStoreResult<&[u8]> {
        let slot = self
            .peer_slots
            .get(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_ref()
            .ok_or(CertStoreError::PlatformError)?;
        slot.get_cert_chain(hash_algo)
            .ok_or(CertStoreError::CertReadError)
    }

    /// Set the supported slots bit mask and initialize PeerSlot entries for any newly supported slots.  
    fn set_supported_slots(&mut self, slot_mask: u8) -> CertStoreResult<()> {
        for b in 0..8 {
            if slot_mask & (1 << b) == 1
                && let Some(slot) = self.peer_slots.get_mut(b as usize)
                && slot.is_none()
            {
                *slot = Some(PeerSlot::default());
            }
        }

        Ok(())
    }

    fn get_supported_slots(&self) -> CertStoreResult<u8> {
        Ok(self.supported_slots_mask)
    }

    fn set_provisioned_slots(&mut self, provisioned_slot_mask: u8) -> CertStoreResult<()> {
        self.provisioned_slots_mask = provisioned_slot_mask;
        Ok(())
    }

    fn get_provisioned_slots(&self) -> CertStoreResult<u8> {
        Ok(self.provisioned_slots_mask)
    }

    /// Set the certificate chain for a given slot. This would typically be called
    /// after successfully reassembling the certificate chain from received portions.
    ///
    /// # Returns
    /// - `Ok(())` if the certificate chain was set successfully
    /// - `Err(CertStoreError)` if there was an error (e.g., invalid slot ID)
    fn set_cert_chain(&mut self, slot_id: u8, cert_chain: &[u8]) -> CertStoreResult<()> {
        let slot = self
            .peer_slots
            .get_mut(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_mut()
            .ok_or(CertStoreError::PlatformError)?;

        slot.cert_chain = cert_chain
            .try_into()
            .map_err(|_| CertStoreError::BufferTooSmall)?;
        Ok(())
    }

    fn get_digest(&self, slot_id: u8) -> CertStoreResult<&[u8]> {
        let slot = self
            .peer_slots
            .get(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_ref()
            .ok_or(CertStoreError::PlatformError)?;
        Ok(&slot.digest)
    }

    /// Set the digest for a given slot, provided by the `DIGESTS` response.
    ///
    /// # Parameters
    /// - `slot_id`: The slot ID to set the digest for
    /// - `digest`: The digest value to set
    fn set_digest(&mut self, slot_id: u8, digest: &[u8]) -> CertStoreResult<()> {
        let slot: &mut PeerSlot = self
            .peer_slots
            .get_mut(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_mut()
            .ok_or(CertStoreError::PlatformError)?;
        slot.digest = digest
            .try_into()
            .map_err(|_| CertStoreError::BufferTooSmall)?;
        Ok(())
    }

    fn get_cert_info(&self, slot_id: u8) -> CertStoreResult<CertificateInfo> {
        let slot = self
            .peer_slots
            .get(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_ref()
            .ok_or(CertStoreError::PlatformError)?;
        slot.certificate_info
            .ok_or(CertStoreError::InvalidSlotId(slot_id))
    }
    fn set_cert_info(&mut self, slot_id: u8, cert_info: CertificateInfo) -> CertStoreResult<()> {
        let slot = self
            .peer_slots
            .get_mut(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_mut()
            .ok_or(CertStoreError::PlatformError)?;
        slot.certificate_info = Some(cert_info);
        Ok(())
    }
    fn get_key_usage_mask(&self, slot_id: u8) -> CertStoreResult<KeyUsageMask> {
        let slot = self
            .peer_slots
            .get(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_ref()
            .ok_or(CertStoreError::PlatformError)?;
        slot.key_usage_mask
            .ok_or(CertStoreError::InvalidSlotId(slot_id))
    }

    fn set_key_usage_mask(
        &mut self,
        slot_id: u8,
        key_usage_mask: KeyUsageMask,
    ) -> CertStoreResult<()> {
        let slot = self
            .peer_slots
            .get_mut(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_mut()
            .ok_or(CertStoreError::PlatformError)?;
        slot.key_usage_mask = Some(key_usage_mask);
        Ok(())
    }

    fn get_keypair(&self, slot_id: u8) -> CertStoreResult<u8> {
        let slot = self
            .peer_slots
            .get(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_ref()
            .ok_or(CertStoreError::PlatformError)?;
        slot.keypair_id
            .ok_or(CertStoreError::InvalidSlotId(slot_id))
    }

    fn set_keypair(&mut self, slot_id: u8, keypair: u8) -> CertStoreResult<()> {
        let slot = self
            .peer_slots
            .get_mut(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_mut()
            .ok_or(CertStoreError::PlatformError)?;
        slot.keypair_id = Some(keypair);
        Ok(())
    }

    fn get_root_hash(&self, slot_id: u8, hash_algo: BaseHashAlgoType) -> CertStoreResult<&[u8]> {
        let slot = self
            .peer_slots
            .get(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_ref()
            .ok_or(CertStoreError::PlatformError)?;
        slot.get_root_hash(hash_algo)
            .ok_or(CertStoreError::CertReadError)
    }

    fn get_requested_msh_type(&self, slot_id: u8) -> CertStoreResult<MeasurementSummaryHashType> {
        self.peer_slots
            .get(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_ref()
            .ok_or(CertStoreError::PlatformError)?
            .requested_msh_type
            .clone()
            .ok_or(CertStoreError::Undefined)
    }

    fn set_requested_msh_type(
        &mut self,
        slot_id: u8,
        msh_type: MeasurementSummaryHashType,
    ) -> CertStoreResult<()> {
        let slot = self
            .peer_slots
            .get_mut(slot_id as usize)
            .ok_or(CertStoreError::InvalidSlotId(slot_id))?
            .as_mut()
            .ok_or(CertStoreError::PlatformError)?;
        slot.requested_msh_type = Some(msh_type);

        Ok(())
    }
}

pub fn create_local_algorithms<'a>() -> LocalDeviceAlgorithms<'a> {
    // Measurement specification (DMTF)
    let mut measurement_spec = MeasurementSpecification::default();
    measurement_spec.set_dmtf_measurement_spec(1);

    // Measurement hash algorithm (SHA-384)
    let mut measurement_hash_algo = MeasurementHashAlgo::default();
    measurement_hash_algo.set_tpm_alg_sha_384(1);

    // Base asymmetric algorithm (ECDSA P-384)
    let mut base_asym_algo = BaseAsymAlgo::default();
    base_asym_algo.set_tpm_alg_ecdsa_ecc_nist_p384(1);

    // Base hash algorithm (SHA-384)
    let mut base_hash_algo = BaseHashAlgo::default();
    base_hash_algo.set_tpm_alg_sha_384(1);

    let device_algorithms = DeviceAlgorithms {
        measurement_spec,
        other_param_support: OtherParamSupport::default(),
        measurement_hash_algo,
        base_asym_algo,
        base_hash_algo,
        mel_specification: MelSpecification::default(),
        dhe_group: DheNamedGroup::default(),
        aead_cipher_suite: AeadCipherSuite::default(),
        req_base_asym_algo: ReqBaseAsymAlg::default(),
        key_schedule: KeySchedule::default(),
    };

    let algorithm_priority_table = AlgorithmPriorityTable {
        measurement_specification: None,
        opaque_data_format: None,
        base_asym_algo: None,
        base_hash_algo: None,
        mel_specification: None,
        dhe_group: None,
        aead_cipher_suite: None,
        req_base_asym_algo: None,
        key_schedule: None,
    };

    LocalDeviceAlgorithms {
        device_algorithms,
        algorithm_priority_table,
    }
}
