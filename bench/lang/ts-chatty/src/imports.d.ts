declare module "bench:web/items@0.1.0" {
  export type Item = { id: bigint; name: string; owner: string; score: number };
  export function all(): Item[];
  export function get(id: bigint): Item;
}
