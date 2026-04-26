/**
 * Poseidon helper backed by circomlibjs.
 *
 * The same Poseidon implementation is used inside the circuit (`circomlib`) and
 * out here in JavaScript (`circomlibjs`), so a JS-side commitment computed by
 * `commitOrigin` matches the circuit's `originCommitment === poseidon.out`
 * constraint without any extra wiring.
 *
 * Loaded lazily so packages that only need types (e.g. the registration script)
 * don't pay the WASM-init cost.
 */
import { buildPoseidon } from "circomlibjs";

type PoseidonFn = ((inputs: bigint[]) => Uint8Array) & {
  F: { toString: (x: Uint8Array | bigint) => string };
};

let cached: PoseidonFn | null = null;

export async function getPoseidon(): Promise<PoseidonFn> {
  if (!cached) {
    cached = (await buildPoseidon()) as PoseidonFn;
  }
  return cached;
}

export async function poseidonHashDecimal(inputs: bigint[]): Promise<string> {
  const p = await getPoseidon();
  return p.F.toString(p(inputs));
}
