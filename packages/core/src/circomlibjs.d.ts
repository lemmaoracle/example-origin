declare module "snarkjs" {
  export const groth16: {
    fullProve(
      input: Record<string, string | bigint>,
      wasmPath: string,
      zkeyPath: string,
    ): Promise<{
      proof: {
        pi_a: string[];
        pi_b: string[][];
        pi_c: string[];
        protocol: string;
        curve: string;
      };
      publicSignals: string[];
    }>;
    verify(
      vkey: unknown,
      publicSignals: readonly string[],
      proof: unknown,
    ): Promise<boolean>;
  };
}

declare module "circomlibjs" {
  export type PoseidonField = {
    toString: (x: Uint8Array | bigint) => string;
  };
  export type Poseidon = ((inputs: bigint[]) => Uint8Array) & {
    F: PoseidonField;
  };
  export function buildPoseidon(): Promise<Poseidon>;
}
