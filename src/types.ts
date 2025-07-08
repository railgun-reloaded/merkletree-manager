type CipherText = {
  ciphertext: string[];
  blindedSenderViewingKey: string;
  blindedReceiverViewingKey: string;
  annotationData: string;
  memo: string;
}

type CommitmentCiphertext = {
  ciphertext: string[];
  blindedSenderViewingKey: string;
  blindedReceiverViewingKey: string;
  annotationData: string;
  memo: string;
}

type SnarkProof = {
  a: {
    x: string;
    y: string;
  };
  b: {
    x: string[];
    y: string[];
  };
  c: {
    x: string;
    y: string;
  };
}

type BoundParams = {
  treeNumber: number;
  minGasPrice: string;
  unshield: number;
  chainID: string;
  adaptContract: string;
  adaptParams: string;
  commitmentCiphertext: CommitmentCiphertext[];
}

export type {
  BoundParams,
  CipherText,
  CommitmentCiphertext,
  SnarkProof,
}
