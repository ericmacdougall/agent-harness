"""goodqa#16136 AC-16: wire GUARD_HELD_ENV into the create-guard and the transcoder mode parse. python3 patch_guard.py REPO"""
import os, sys
R = sys.argv[1]


def patch(rel, pairs):
    p = os.path.join(R, rel); t = open(p).read()
    for old, new in pairs:
        assert t.count(old) == 1, (rel, t.count(old), old[:80])
        t = t.replace(old, new)
    open(p, 'w').write(t)


patch('apps/transcoder/src/index.ts', [
    ("import { runTranscribeMode } from './transcribe';", "import { transcoderMode } from './mode';\nimport { runTranscribeMode } from './transcribe';"),
    ("  if (process.env.TRANSCODER_MODE === 'transcribe') {", "  const mode = transcoderMode(process.env);\n  if (mode === 'transcribe') {"),
    ("  if (process.env.TRANSCODER_MODE === 'frames') {", "  if (mode === 'frames') {"),
])

patch('apps/job-dispatcher/src/create-guard.ts', [
    ("""  allowedImages: readonly string[];
  /** Bounds how much of a `/containers/create` body this process will buffer before parsing. */""",
     """  allowedImages: readonly string[];
  /**
   * goodqa#16136: a mode hold (`GUARD_HELD_ENV`, see held-env.ts). Null or
   * absent: no hold, exactly the behaviour before it existed.
   */
  heldEnv?: HeldEnv | null;
  /** Bounds how much of a `/containers/create` body this process will buffer before parsing. */"""),
    ("""export function validateContainerCreateBody(body: unknown, allowedImages: readonly string[]): CreateBodyValidation {""",
     """export function validateContainerCreateBody(
  body: unknown,
  allowedImages: readonly string[],
  heldEnv: HeldEnv | null = null,
): CreateBodyValidation {"""),
    ("""      reason: `Image must be one of the ${allowedImages.length} pre-approved job images, got ${JSON.stringify(image)}`,
    };
  }
""", """      reason: `Image must be one of the ${allowedImages.length} pre-approved job images, got ${JSON.stringify(image)}`,
    };
  }

  const heldReason = heldEnvViolation(top, heldEnv);
  if (heldReason) return { ok: false, reason: heldReason };
"""),
    ("""        const validation = validateContainerCreateBody(parsed, config.allowedImages);""",
     """        const validation = validateContainerCreateBody(parsed, config.allowedImages, config.heldEnv ?? null);"""),
])
p = os.path.join(R, 'apps/job-dispatcher/src/create-guard.ts'); t = open(p).read()
first_import = t.index('\nimport ')
t = t[:first_import] + "\nimport { heldEnvViolation, type HeldEnv } from './held-env';" + t[first_import:]
open(p, 'w').write(t)

patch('apps/job-dispatcher/src/create-guard-main.ts', [
    ("import { isDigestPinnedImage } from './config';", "import { isDigestPinnedImage } from './config';\nimport { parseHeldEnv, type HeldEnv } from './held-env';"),
    ("""  JOB_IMAGE_SUGGEST_FIX_WORKER: z.string().default(''),
});""", """  JOB_IMAGE_SUGGEST_FIX_WORKER: z.string().default(''),
  /**
   * goodqa#16136: a mode hold, e.g. `TRANSCODER_MODE=transcribe` (held-env.ts).
   * Empty: no hold. Anything else that is not one supported pair refuses startup.
   */
  GUARD_HELD_ENV: z.string().default(''),
});"""),
    ("""  allowedImages: string[];
  maxCreateBodyBytes: number;""", """  allowedImages: string[];
  heldEnv: HeldEnv | null;
  maxCreateBodyBytes: number;"""),
    ("""  const parsed = envSchema.parse(env);""", """  const parsed = envSchema.parse(env);
  const heldEnv = parseHeldEnv(parsed.GUARD_HELD_ENV);"""),
    ("""    allowedImages,
    maxCreateBodyBytes: parsed.GUARD_MAX_CREATE_BODY_BYTES,""", """    allowedImages,
    heldEnv,
    maxCreateBodyBytes: parsed.GUARD_MAX_CREATE_BODY_BYTES,"""),
    ("""allowedImages=${config.allowedImages.length}`,""",
     """allowedImages=${config.allowedImages.length}, heldEnv=${config.heldEnv ? `${config.heldEnv.key}=${config.heldEnv.value}` : 'none'}`,"""),
])
print('patched guard')
