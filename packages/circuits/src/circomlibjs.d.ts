declare module "circomlibjs" {
  // Minimal type surface — circomlibjs has no published @types; we only need
  // buildPoseidon for hashing inside the input generators.
  export type PoseidonField = {
    toString: (x: Uint8Array | bigint) => string;
  };
  export type Poseidon = ((inputs: bigint[]) => Uint8Array) & {
    F: PoseidonField;
  };
  export function buildPoseidon(): Promise<Poseidon>;
}
