import { ulid } from "ulid";

declare const brand: unique symbol;
export type Branded<T, B extends string> = T & { readonly [brand]: B };

export const ID_PREFIXES = ["run", "act", "dec", "apr", "evt"] as const;
export type IdPrefix = (typeof ID_PREFIXES)[number];
export type PrefixedId<P extends IdPrefix> = Branded<string, P>;
export type RunId = PrefixedId<"run">;
export type ActionId = PrefixedId<"act">;
export type DecisionId = PrefixedId<"dec">;
export type ApprovalId = PrefixedId<"apr">;
export type EventId = PrefixedId<"evt">;

export const ID_BODY = /^[0-9A-HJKMNP-TV-Z]{26}$/;

export function newId<P extends IdPrefix>(prefix: P): PrefixedId<P> {
  return `${prefix}_${ulid()}` as PrefixedId<P>;
}

export function parseId<P extends IdPrefix>(prefix: P, value: unknown): PrefixedId<P> | null {
  if (typeof value !== "string") return null;
  const head = `${prefix}_`;
  if (!value.startsWith(head)) return null;
  const body = value.slice(head.length);
  return ID_BODY.test(body) ? (value as PrefixedId<P>) : null;
}
