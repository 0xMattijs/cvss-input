import { useMemo } from 'react';
import { evaluate } from '../core/evaluate';
import type { CvssResult, EvaluateOptions } from '../core/types';

/** Parses, validates, and scores a vector. Recomputes only when an input changes. */
export function useCvss(vector: string, options: EvaluateOptions = {}): CvssResult {
  const { version, strict, baseVector } = options;
  return useMemo(
    () => evaluate(vector, { version, strict, baseVector }),
    [vector, version, strict, baseVector],
  );
}
