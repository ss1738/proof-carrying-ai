(** * The general rule engine, machine-checked (axiom-free).

    The pcai certificate (pcai/certificate.py) verifies a list of per-rule ZK proofs and then checks that the
    proven rules COVER the policy. This file machine-checks why that coverage check is both sufficient and
    necessary -- it is the formal counterpart of the 0.3.2 "completeness" soundness fix.

    Checked by coqc (Rocq 9.2). *)

Require Import List Bool.
Import ListNotations.

Section RuleEngine.

Variable Action : Type.

Definition Rule := Action -> bool.          (* a decidable predicate on an action *)
Definition Policy := list Rule.

(* An action is compliant with a policy iff EVERY rule accepts it (a conjunction). *)
Definition evaluate (p : Policy) (a : Action) : bool := forallb (fun r => r a) p.
Definition compliant (p : Policy) (a : Action) : Prop := evaluate p a = true.

(** COVERAGE IS SUFFICIENT. A certificate carries a proof for each rule in `proven`; the verifier accepts only
    if `policy` is covered by `proven` (every policy rule was proven). Then the action is policy-compliant:
    each policy rule is among the proven rules, all of which hold. *)
Theorem coverage_sound :
  forall (policy proven : Policy) (a : Action),
    evaluate proven a = true -> incl policy proven -> compliant policy a.
Proof.
  intros policy proven a Hpr Hincl.
  unfold compliant, evaluate in *.
  apply forallb_forall. intros r Hr.
  rewrite forallb_forall in Hpr.
  apply Hpr, Hincl, Hr.
Qed.

(** COVERAGE IS NECESSARY. If a certificate omits a policy rule (here: proves nothing, `[]`), an action can
    satisfy the proven rules yet violate the policy. This is exactly the dropped-rule attack: without the
    coverage check, an incomplete certificate would be accepted. *)
Theorem omission_unsound :
  forall (r0 : Rule) (a : Action),
    r0 a = false -> evaluate [] a = true /\ evaluate [r0] a = false.
Proof.
  intros r0 a Hf. split.
  - reflexivity.
  - simpl. rewrite Hf. reflexivity.
Qed.

(** Adding a rule only restricts the accepted set (defence-in-depth is monotone-safe). *)
Theorem adding_a_rule_only_restricts :
  forall (p : Policy) (r : Rule) (a : Action),
    evaluate (r :: p) a = true -> evaluate p a = true.
Proof.
  intros p r a H. unfold evaluate in *. simpl in H.
  apply andb_true_iff in H. destruct H as [_ Hp]. exact Hp.
Qed.

End RuleEngine.

(* Print Assumptions coverage_sound.  (* -> Closed under the global context: axiom-free *) *)
