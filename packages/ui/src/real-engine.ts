// Indirection so the real engine module is only resolved when it is actually requested
// (keeps `?mock` dev sessions independent of it). Imported only via dynamic import().
export { getEngine } from "@segv/engine";
