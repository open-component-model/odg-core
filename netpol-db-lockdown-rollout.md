# DB network-policy lockdown — merge order

## One rule

**Labels first, lockdown second.**
The charts give pods a label. The database only lets pods in that have the label.
If you lock down before the labels are there, pods cannot reach the database.

---

## Step 1 — merge odg-core

Merge branch `network-policy` (charts) + PR #1255 (otlp default).

This one release contains everything odg-dev (gardener) needs:

1. charts = pods get the `delivery-db-client=true` label
2. extension-definitions.yaml = database lockdown (`allowExternal: false`)

Both ship together in one release. No second step for odg-dev.

> For a moment during the rollout the database may lock down before some pods
> get their label. Those pods restart-notReady for a short time, then heal
> themselves. Normal on a dev cluster.

---

## Step 2 — wait for the release on OCP

The OCP database **values** do not come from odg-core. They come from the
environments repo. So for OCP you must wait:

- [ ] odg-core release is live on OCP
- [ ] `kubectl get pods -n odg-system` shows label `delivery-db-client=true`
  on `delivery-service`, `access-manager`, `cache-manager`, `delivery-db-backup`

---

## Step 3 — merge environments

`ocp-environments`:

- `bootstrap/extra-manifests/odg.serviceprovider.yaml`
- `resources/openmcp/extra/odg.serviceprovider.yaml`

(sets `allowExternal: false` + `allowExternalEgress: false` for the OCP database)

---

## Step 4 — check

```sh
# delivery-service still healthy, meaning it still reaches the DB:
kubectl get deploy delivery-service -n odg-system          # OCP
kubectl get deploy delivery-service -n delivery            # odg-dev

# label in place / lockdown in place:
kubectl get pods -n odg-system --show-labels | grep delivery-db-client
kubectl get netpol delivery-db -n odg-system -o yaml | grep -B2 "from:"
```

If delivery-service stays Ready on both clusters after the merge: done.

---

## Numbers cheat sheet

| Cluster | Database lockdown comes from | Extra step needed? |
|---|---|---|
| odg-dev (gardener, ns `delivery`) | odg-core `extension-definitions.yaml` | no |
| OCP (`openmcp`, ns `odg-system`) | environments `odg.serviceprovider.yaml` | yes: wait for step 1 on the cluster first |

Nothing needed in `~/code/github.tools.sap/odg-dev` or
`~/code/github.tools.sap/environments-modg`.
