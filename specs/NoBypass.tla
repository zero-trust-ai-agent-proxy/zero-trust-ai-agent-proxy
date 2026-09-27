---- MODULE NoBypass ----
EXTENDS Naturals, TLC

CONSTANTS Agents
VARIABLES svid, svidVer, svidExp, revoked, attestUntil, policy, policyVer, trust, decision, now

Tau == 1
MaxTime == 3
Versions == 0..3

Valid(a) == /\ svid[a]
            /\ now < svidExp[a]
            /\ ~revoked[a]
            /\ now < attestUntil[a]
            /\ policy[a]
            /\ trust[a] > Tau

Init == /\ now = 0
        /\ svid = [a \in Agents |-> TRUE]
        /\ svidVer = [a \in Agents |-> 0]
        /\ svidExp = [a \in Agents |-> 2]
        /\ revoked = [a \in Agents |-> FALSE]
        /\ attestUntil = [a \in Agents |-> 2]
        /\ policy = [a \in Agents |-> TRUE]
        /\ policyVer = 0
        /\ trust = [a \in Agents |-> 2]
        /\ decision = [a \in Agents |-> "deny"]

Deny(a) == /\ decision' = [decision EXCEPT ![a] = "deny"]
           /\ UNCHANGED <<svid, svidVer, svidExp, revoked, attestUntil, policy, policyVer, trust, now>>

Allow(a) == /\ Valid(a)
            /\ decision' = [decision EXCEPT ![a] = "allow"]
            /\ UNCHANGED <<svid, svidVer, svidExp, revoked, attestUntil, policy, policyVer, trust, now>>

RotateSVID(a) == /\ svid' = [svid EXCEPT ![a] = TRUE]
                 /\ svidExp' = [svidExp EXCEPT ![a] = MaxTime]
                 /\ svidVer' = [svidVer EXCEPT ![a] = (svidVer[a] + 1) % 4]
                 /\ revoked' = [revoked EXCEPT ![a] = FALSE]
                 /\ decision' = [decision EXCEPT ![a] = "deny"]
                 /\ UNCHANGED <<attestUntil, policy, policyVer, trust, now>>

ExpireSVID(a) == /\ svidExp' = [svidExp EXCEPT ![a] = now]
                 /\ svid' = [svid EXCEPT ![a] = FALSE]
                 /\ decision' = [decision EXCEPT ![a] = "deny"]
                 /\ UNCHANGED <<svidVer, revoked, attestUntil, policy, policyVer, trust, now>>

RevokeSVID(a) == /\ revoked' = [revoked EXCEPT ![a] = TRUE]
                 /\ decision' = [decision EXCEPT ![a] = "deny"]
                 /\ UNCHANGED <<svid, svidVer, svidExp, attestUntil, policy, policyVer, trust, now>>

RefreshAttestation(a) == /\ attestUntil' = [attestUntil EXCEPT ![a] = MaxTime]
                         /\ decision' = [decision EXCEPT ![a] = "deny"]
                         /\ UNCHANGED <<svid, svidVer, svidExp, revoked, policy, policyVer, trust, now>>

ExpireAttestation(a) == /\ attestUntil' = [attestUntil EXCEPT ![a] = now]
                        /\ decision' = [decision EXCEPT ![a] = "deny"]
                        /\ UNCHANGED <<svid, svidVer, svidExp, revoked, policy, policyVer, trust, now>>

PolicyUpdate(a) == /\ policy' = [policy EXCEPT ![a] = ~policy[a]]
                   /\ policyVer' = (policyVer + 1) % 4
                   /\ decision' = [decision EXCEPT ![a] = "deny"]
                   /\ UNCHANGED <<svid, svidVer, svidExp, revoked, attestUntil, trust, now>>

TrustFeedback(a) == /\ \E v \in 0..2: trust' = [trust EXCEPT ![a] = v]
                    /\ decision' = [decision EXCEPT ![a] = "deny"]
                    /\ UNCHANGED <<svid, svidVer, svidExp, revoked, attestUntil, policy, policyVer, now>>

ConcurrentRotateExpire(a, b) == /\ a # b
                                /\ svid' = [svid EXCEPT ![a] = TRUE, ![b] = FALSE]
                                /\ svidExp' = [svidExp EXCEPT ![a] = MaxTime, ![b] = now]
                                /\ svidVer' = [svidVer EXCEPT ![a] = (svidVer[a] + 1) % 4]
                                /\ revoked' = [revoked EXCEPT ![a] = FALSE]
                                /\ decision' = [a0 \in Agents |-> "deny"]
                                /\ UNCHANGED <<attestUntil, policy, policyVer, trust, now>>

ConcurrentRevokePolicy(a, b) == /\ a # b
                                /\ revoked' = [revoked EXCEPT ![a] = TRUE]
                                /\ policy' = [policy EXCEPT ![b] = ~policy[b]]
                                /\ policyVer' = (policyVer + 1) % 4
                                /\ decision' = [a0 \in Agents |-> "deny"]
                                /\ UNCHANGED <<svid, svidVer, svidExp, attestUntil, trust, now>>

Tick == /\ now < MaxTime
        /\ now' = now + 1
        /\ decision' = [a \in Agents |->
             IF /\ decision[a] = "allow"
                /\ svid[a]
                /\ now + 1 < svidExp[a]
                /\ ~revoked[a]
                /\ now + 1 < attestUntil[a]
                /\ policy[a]
                /\ trust[a] > Tau
             THEN "allow" ELSE "deny"]
        /\ UNCHANGED <<svid, svidVer, svidExp, revoked, attestUntil, policy, policyVer, trust>>

Next == \/ Tick
        \/ \E a \in Agents: Deny(a) \/ Allow(a) \/ RotateSVID(a) \/ ExpireSVID(a) \/ RevokeSVID(a)
        \/ \E a \in Agents: RefreshAttestation(a) \/ ExpireAttestation(a) \/ PolicyUpdate(a) \/ TrustFeedback(a)
        \/ \E a, b \in Agents: ConcurrentRotateExpire(a, b) \/ ConcurrentRevokePolicy(a, b)

NoBypass == \A a \in Agents: decision[a] = "allow" => Valid(a)
====
