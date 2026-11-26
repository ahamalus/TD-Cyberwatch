import { type ComponentType, lazy } from "react";

/**
 * Lazily loaded page module: `lazyModule<typeof import("./x")>(() => import("./x")).SomePage` is a
 * React.lazy component that loads the module the first time any of its pages renders. Each export gets
 * one stable lazy component; only component exports may be used this way.
 */
export function lazyModule<M extends object>(load: () => Promise<M>): M {
  let pending: Promise<M> | null = null;
  const cache = new Map<PropertyKey, ComponentType<unknown>>();
  return new Proxy({} as M, {
    get(_, name) {
      if (!cache.has(name)) {
        cache.set(name, lazy(async () => {
          pending ??= load();
          const mod = (await pending) as Record<PropertyKey, ComponentType<unknown>>;
          return { default: mod[name] };
        }));
      }
      return cache.get(name);
    },
  });
}
