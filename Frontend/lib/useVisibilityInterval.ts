import { useEffect, useRef } from "react";

type IntervalCallback = () => void | Promise<void>;

/** Poll only while this tab is visible, and never stack overlapping polls. */
export function useVisibilityInterval(callback: IntervalCallback, delay: number) {
  const callbackRef = useRef(callback);
  const inFlightRef = useRef(false);

  useEffect(() => {
    callbackRef.current = callback;
  }, [callback]);

  useEffect(() => {
    const run = async () => {
      if (document.visibilityState !== "visible" || inFlightRef.current) return;
      inFlightRef.current = true;
      try {
        await callbackRef.current();
      } catch {
        // The page's initial load and manual refresh own visible error states.
      } finally {
        inFlightRef.current = false;
      }
    };

    const onVisibilityChange = () => {
      if (document.visibilityState === "visible") void run();
    };

    const interval = window.setInterval(() => void run(), delay);
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => {
      window.clearInterval(interval);
      document.removeEventListener("visibilitychange", onVisibilityChange);
    };
  }, [delay]);
}
