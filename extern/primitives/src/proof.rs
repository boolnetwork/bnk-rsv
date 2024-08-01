use codec::{Decode, Encode, alloc::vec::Vec};

#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug)]
pub enum OnChainProof {
    State(StateProof),
}

impl OnChainProof {
    pub fn verify(&self, witness: &[u8]) -> bool {
        match self {
            OnChainProof::State(proof) => proof.verify(witness),
        }
    }

    pub fn data(&self) -> Vec<u8> {
        match self {
            OnChainProof::State(proof) => proof.data.clone(),
        }
    }
}

#[derive(Encode, Decode, Clone, PartialEq, Eq, Debug)]
pub struct StateProof {
    pub signature: Vec<u8>,
    pub data: Vec<u8>,
}

impl StateProof {
    pub fn verify(&self, pk: &[u8]) -> bool {
        super::crypto::ed25519_verify(pk, &self.data, &self.signature)
    }
}
