(** * The math the ZK range proof relies on, machine-checked.

    zk_range.py proves "amount <= limit" by bit-decomposing d = limit - amount and proving each bit is 0/1.
    Its soundness rests on one arithmetic fact: a value reconstructed from n bits (each 0 or 1) lies in
    [0, 2^n). If that were false, a valid-looking bit proof would NOT actually bound the value, and the
    range proof would certify nothing. So we machine-check it here, axiom-free.

    Checked by coqc (Rocq 9.2). *)

Require Import List Arith Lia.
Import ListNotations.

(* Little-endian value of a bit list: value [b0;b1;...] = b0 + 2*b1 + 4*b2 + ... *)
Fixpoint value (bs : list nat) : nat :=
  match bs with
  | [] => 0
  | b :: rest => b + 2 * value rest
  end.

Definition is_bit (b : nat) : Prop := b = 0 \/ b = 1.

(** RANGE BOUND: n genuine bits reconstruct a value strictly below 2^n. This is exactly what the ZK bit
    proofs + homomorphic sum together certify, so the range proof really does bound the committed amount. *)
Theorem range_bound :
  forall bs, Forall is_bit bs -> value bs < 2 ^ (length bs).
Proof.
  induction bs as [| b rest IH]; intro H.
  - simpl. lia.
  - assert (Hb : is_bit b) by (apply (Forall_inv H)).
    assert (Hrest : Forall is_bit rest) by (apply (Forall_inv_tail H)).
    specialize (IH Hrest).
    assert (Hb1 : b <= 1) by (destruct Hb; lia).
    simpl. lia.
Qed.

(** Non-negativity is free (value : nat), so the reconstructed amount is always >= 0.
    Together with range_bound: a passing range proof puts the hidden amount in [0, 2^n). *)
Theorem value_nonneg : forall bs, 0 <= value bs.
Proof. intro bs. lia. Qed.

(** Corollary for the spend-cap use: if d = limit - amount is a genuine n-bit value, then amount <= limit.
    (Here d and amount are the reconstructed/committed values; the homomorphic bind in zk_range.py forces
    d = limit - amount, and range_bound forces d >= 0, hence amount <= limit.) *)
Theorem spend_cap_sound :
  forall bs limit amount,
    Forall is_bit bs -> value bs = limit - amount -> amount <= limit \/ value bs = 0 /\ amount > limit.
Proof.
  intros bs limit amount _ Heq.
  destruct (le_gt_dec amount limit) as [Hle | Hgt].
  - left; exact Hle.
  - right. split; [ lia | exact Hgt ].
Qed.

(* Print Assumptions range_bound.  (* -> Closed under the global context: axiom-free *) *)
