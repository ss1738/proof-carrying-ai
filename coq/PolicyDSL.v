(** * A general policy DSL for agent actions, with machine-checked compositional soundness.

    Compliance.v proved the single-predicate case. This generalizes to a real POLICY: a composable
    conjunction of rules (spend caps, allowlists, no-secret, data-residency, ...) over structured agent
    actions. The machine-checked results below are what make a *general* proof-carrying certificate sound:

    - policy_conjunction_sound : a policy ALLOWS an action iff EVERY rule passes (no rule is silently skipped).
    - policy_blocks_on_violation : if ANY rule is violated, the policy BLOCKS (no action slips a broken rule).
    - allowed_set_exact : the set the ZK layer proves membership in is EXACTLY the compliant actions.

    Checked by coqc (Rocq 9.2), no axioms. Parametric in the Action type, so it covers any structured action
    (a payment, a tool call, a git op), not just one domain. *)

Require Import List Bool.
Import ListNotations.

Section PolicyDSL.

  Variable Action : Type.
  (* A rule is a decidable predicate over an action (true = the rule is satisfied). *)
  Definition Rule := Action -> bool.
  (* A policy is a list of rules, combined by conjunction. *)
  Definition Policy := list Rule.

  (* ALLOW iff every rule passes. *)
  Definition evaluate (p : Policy) (a : Action) : bool := forallb (fun rule => rule a) p.
  Definition compliant (p : Policy) (a : Action) : Prop := evaluate p a = true.

  (** COMPOSITIONAL SOUNDNESS: the policy admits an action iff every constituent rule admits it. *)
  Theorem policy_conjunction_sound :
    forall p a, evaluate p a = true <-> (forall rule, In rule p -> rule a = true).
  Proof.
    intros p a. unfold evaluate. rewrite forallb_forall. reflexivity.
  Qed.

  (** NO BYPASS: a single violated rule forces BLOCK, whatever the other rules say. *)
  Theorem policy_blocks_on_violation :
    forall p a rule, In rule p -> rule a = false -> evaluate p a = false.
  Proof.
    intros p a rule Hin Hf. unfold evaluate. apply not_true_is_false. intro Hall.
    rewrite forallb_forall in Hall. specialize (Hall rule Hin). rewrite Hf in Hall. discriminate.
  Qed.

  (** MONOTONICITY: adding a rule can only tighten the policy (never admits more). Defence-in-depth is safe. *)
  Theorem adding_a_rule_only_restricts :
    forall p r a, evaluate (r :: p) a = true -> evaluate p a = true.
  Proof.
    intros p r a H. unfold evaluate in *. simpl in H. apply andb_true_iff in H. tauto.
  Qed.

  (** ALLOWED-SET EXACTNESS: what the ZK membership proof certifies == genuine compliance. *)
  Variable universe : list Action.
  Definition allowed_set (p : Policy) : list Action := filter (evaluate p) universe.
  Theorem allowed_set_exact :
    forall p a, In a (allowed_set p) <-> (In a universe /\ compliant p a).
  Proof.
    intros p a. unfold allowed_set, compliant. apply filter_In.
  Qed.

End PolicyDSL.
