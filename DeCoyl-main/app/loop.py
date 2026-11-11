"""The closed loop from the paper: attacker -> defender -> retrain -> measure.

A learning detector (logistic regression over email text) starts knowing only a
few phishing tactics. Each round an attacker introduces a new tactic; the
detector misses it, those misses feed back into its training data, and it
retrains. A frozen baseline (trained once on the seed) never learns.

Detection rate and false-positive rate are measured each round on a fixed,
held-out test set that spans every tactic, so the numbers are real, not staged.
The test set uses fresh instances (new names, amounts, links), so this measures
recall on unseen instances of each tactic.
"""

import random

from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline

from . import corpus

SEED_FAMILIES = 3   # tactics the detector knows before the loop starts


def _new_model():
    return make_pipeline(
        CountVectorizer(lowercase=True, ngram_range=(1, 2)),
        LogisticRegression(max_iter=1000),
    )


def _fit(pool):
    model = _new_model()
    model.fit([t for t, _ in pool], [y for _, y in pool])
    return model


def _metrics(model, test):
    """Detection rate (recall on phishing) and false-positive rate, as percents."""
    texts = [t for t, _ in test]
    labels = [y for _, y in test]
    pred = model.predict(texts)
    tp = fn = fp = tn = 0
    for p, y in zip(pred, labels):
        if y == 1:
            tp, fn = (tp + 1, fn) if p == 1 else (tp, fn + 1)
        else:
            fp, tn = (fp + 1, tn) if p == 1 else (fp, tn + 1)
    detection = round(100 * tp / (tp + fn)) if (tp + fn) else 0
    fpr = round(100 * fp / (fp + tn)) if (fp + tn) else 0
    return detection, fpr


def run_loop(rounds=5, seed=7):
    """Run the loop and return the round-by-round metrics curve."""
    rng = random.Random(seed)
    all_fams = corpus.PHISH_FAMILIES
    rounds = max(1, min(rounds, len(all_fams) - SEED_FAMILIES))

    # Fixed held-out test set: every tactic + legit mail, test-only wording.
    trng = random.Random(seed + 99)
    test = corpus.gen_phish(all_fams, 4, trng, "test") + corpus.gen_ham(4, trng, "test")

    # Seed training pool: only the first few tactics, train-only wording.
    known = all_fams[:SEED_FAMILIES]
    pool = corpus.gen_phish(known, 5, rng, "train") + corpus.gen_ham(5, rng, "train")
    learner = _fit(pool)
    baseline = _fit(pool)          # trained once, then frozen

    def row(r, misses):
        ld, lf = _metrics(learner, test)
        bd, bf = _metrics(baseline, test)
        return {"round": r, "known": len(known), "misses": misses,
                "learner_detection": ld, "learner_fp": lf,
                "baseline_detection": bd, "baseline_fp": bf}

    curve = [row(0, None)]
    remaining = all_fams[SEED_FAMILIES:]
    for r in range(1, rounds + 1):
        if remaining:
            known = known + [remaining.pop(0)]   # attacker reveals a new tactic
        batch = corpus.gen_phish(known, 5, rng, "train") + corpus.gen_ham(3, rng, "train")

        # How many of the attacker's phishing emails evade the current learner?
        texts = [t for t, _ in batch]
        misses = sum(1 for p, (_, y) in zip(learner.predict(texts), batch)
                     if y == 1 and p == 0)

        # Feed the batch back into training and retrain. Baseline does not.
        pool += batch
        learner = _fit(pool)
        curve.append(row(r, misses))

    final = curve[-1]
    return {
        "rounds": rounds,
        "seed_families": SEED_FAMILIES,
        "total_families": len(all_fams),
        "curve": curve,
        "summary": {
            "learner_detection": final["learner_detection"],
            "baseline_detection": final["baseline_detection"],
            "learner_fp": final["learner_fp"],
            "lift": final["learner_detection"] - final["baseline_detection"],
        },
    }
