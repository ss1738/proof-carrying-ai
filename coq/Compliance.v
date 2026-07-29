(** * Proof-Carrying Compliance: the machine-checked soundness bridge.

    A "proof-carrying agent action" ships a CERTIFICATE with two layers:

    1. A ZERO-KNOWLEDGE proof (the crypto layer; see the qedra Sigma/Pedersen ZK reused
       in demo_certificate.py) that the hidden action's committed value lies in the
       policy's ALLOWED SET - i.e. it proves set-membership without revealing the action.

    2. This MACHINE-CHECKED proof (the logic layer) that the allowed set IS exactly the
       set of policy-compliant actions. It closes the gap the ZK layer leaves open:
       "membership in the allowed set" must actually mean "obeys the policy", or the
       certificate proves nothing meaningful.

    Together: a verifying certificate implies the (hidden) action obeyed the formal policy.

    Checked by coqc (Rocq 9.2), no axioms (Print Assumptions = Closed under the global context). *)

Require Import List Bool.
Import ListNotations.

Section ProofCarryingCompliance.

  (* A formal policy is a decidable predicate over encoded actions: true = ALLOW. *)
  Variable policy : nat -> bool.
  (* The universe of encodable actions the ZK commitment ranges over. *)
  Variable universe : list nat.

  (* The ALLOWED SET the ZK layer proves membership in: the policy-passing actions. *)
  Definition allowed_set : list nat := filter policy universe.

  (* An action is COMPLIANT iff the policy admits it. *)
  Definition compliant (a : nat) : Prop := policy a = true.

  (** SOUNDNESS: a certificate that proves membership in the allowed set proves
      genuine policy compliance. This is what makes the ZK proof mean something -
      an attacker cannot get a verifying certificate for a non-compliant action,
      because the allowed set contains only compliant actions. *)
  Theorem certificate_sound :
    forall a, In a allowed_set -> compliant a.
  Proof.
    intros a Hin. unfold allowed_set in Hin. apply filter_In in Hin.
    unfold compliant. tauto.
  Qed.

  (** COMPLETENESS: every compliant action in the universe is certifiable, so the
      gate never refuses a legitimate action (no false blocks at the logic layer). *)
  Theorem certificate_complete :
    forall a, In a universe -> compliant a -> In a allowed_set.
  Proof.
    intros a Huniv Hc. unfold allowed_set. apply filter_In. split; assumption.
  Qed.

  (** EXACTNESS: membership in the allowed set is EQUIVALENT to being a compliant
      action of the universe. The certificate certifies compliance, nothing more, nothing less. *)
  Theorem certificate_exact :
    forall a, In a allowed_set <-> (In a universe /\ compliant a).
  Proof.
    intro a. unfold allowed_set, compliant. apply filter_In.
  Qed.

End ProofCarryingCompliance.
