(* Independent check of the arithmetic behind poly_mul() in src/poly.c, with a
   computer algebra system (not a proof checker). Run on a remote host:
     wolframscript -file proofs/poly_identity.wl
   Expected output: identity True; sums fit 64 bits; excess of limb 1 below 4096.
   WP proves the same facts from the C code (assertion "product", the overflow
   guards, ztl_poly_h_ok). *)
B = 2^26; P = 2^130 - 5;
A = a0 + a1 B + a2 B^2 + a3 B^3 + a4 B^4;
R = r0 + r1 B + r2 B^2 + r3 B^3 + r4 B^4;
{s1, s2, s3, s4} = 5 {r1, r2, r3, r4};
d0 = a0 r0 + a1 s4 + a2 s3 + a3 s2 + a4 s1;
d1 = a0 r1 + a1 r0 + a2 s4 + a3 s3 + a4 s2;
d2 = a0 r2 + a1 r1 + a2 r0 + a3 s4 + a4 s3;
d3 = a0 r3 + a1 r2 + a2 r1 + a3 r0 + a4 s4;
d4 = a0 r4 + a1 r3 + a2 r2 + a3 r1 + a4 r0;
fold = (a1 r4 + a2 r3 + a3 r2 + a4 r1) + (a2 r4 + a3 r3 + a4 r2) B + (a3 r4 + a4 r3) B^2 + (a4 r4) B^3;
(* The five sums are the product minus (2^130 - 5) times the part at 2^130 and above. *)
Print["identity: ", Expand[(d0 + d1 B + d2 B^2 + d3 B^3 + d4 B^4) - (A R - P fold)] === 0];
(* Worst case under the contract of poly_mul: a_i <= 2^28 - 1, r_i <= 2^26 - 1.
   Every term grows with every input, so the largest inputs give the largest values. *)
mx = {a0 -> 2^28 - 1, a1 -> 2^28 - 1, a2 -> 2^28 - 1, a3 -> 2^28 - 1, a4 -> 2^28 - 1,
      r0 -> 2^26 - 1, r1 -> 2^26 - 1, r2 -> 2^26 - 1, r3 -> 2^26 - 1, r4 -> 2^26 - 1};
D0 = d0 /. mx; D1 = d1 /. mx; D2 = d2 /. mx; D3 = d3 /. mx; D4 = d4 /. mx;
e1 = D1 + Quotient[D0, B]; e2 = D2 + Quotient[e1, B]; e3 = D3 + Quotient[e2, B]; e4 = D4 + Quotient[e3, B];
t = (B - 1) + Quotient[e4, B] 5;
Print["max sum d (bits): ", N[Log2[Max[D0, D1, D2, D3, D4]]], "  fits 64 bits: ", Max[e1, e2, e3, e4] < 2^64];
Print["max last carry: ", Quotient[e4, B], " (bits ", N[Log2[Quotient[e4, B]]], ")"];
Print["max excess of limb 1: ", Quotient[t, B], "  within slack 4096: ", Quotient[t, B] < 4096];
