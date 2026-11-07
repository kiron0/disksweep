"""Revalidate a signed plan without changing candidate files."""
from _protocol import run
from _core import Store, load_plan

def validate(request):
    plan = load_plan(Store(request["state_dir"]), request["plan_id"])
    return {"valid": True, "plan_id": plan["id"], "candidate_count": len(plan["entries"])}

if __name__ == "__main__":
    run(validate)
