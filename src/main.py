import json
import argparse

def format_change(change):
    """Formats the resource change in JSON-like diff format."""
    before = change.get("before", {})
    after = change.get("after", {})

    diff_lines = ["```diff"]

    def recursive_diff(before, after, indent=0):
        """Recursively finds and formats only the changed attributes."""
        spaces = " " * indent

        if isinstance(before, dict) and isinstance(after, dict):
            for key in before.keys() | after.keys():
                if key not in before:
                    diff_lines.append(f'{spaces}+ "{key}": {json.dumps(after[key], indent=2)},')
                elif key not in after:
                    diff_lines.append(f'{spaces}- "{key}": {json.dumps(before[key], indent=2)},')
                elif before[key] != after[key]:  # Only show changed attributes
                    diff_lines.append(f'{spaces}"{key}": [')
                    recursive_diff(before[key], after[key], indent + 2)
                    diff_lines.append(f"{spaces}],")

        elif isinstance(before, list) and isinstance(after, list):
            if all(isinstance(item, str) for item in before + after):  # Handle lists of strings
                removed = set(before) - set(after)
                added = set(after) - set(before)
                for item in removed:
                    diff_lines.append(f'- {spaces}"{item}",')
                for item in added:
                    diff_lines.append(f'+ {spaces}"{item}",')
            elif all(isinstance(item, dict) for item in before + after):  # Handle lists of dicts
                for old_item, new_item in zip(before, after):
                    diff_lines.append(f'{spaces}{{')
                    recursive_diff(old_item, new_item, indent + 2)
                    diff_lines.append(f"{spaces}}},")

        else:
            diff_lines.append(f'- {spaces}{json.dumps(before)},')
            diff_lines.append(f'+ {spaces}{json.dumps(after)},')

    recursive_diff(before, after)

    diff_lines.append("```")
    return "\n".join(diff_lines)

def process_tf_plan(json_path):
    """Processes the Terraform plan JSON and generates a Markdown summary."""
    with open(json_path, "r") as f:
        plan = json.load(f)

    md_output = []

    for change in plan.get("resource_changes", []):
        actions = change["change"]["actions"]
        if not set(actions) & {"create", "update", "delete"}:
            continue  # Skip no-op changes

        md_output.append(f"### `{change['address']}` will be **{actions[0]}**\n")
        formatted_diff = format_change(change["change"])
        if formatted_diff:
            md_output.append(formatted_diff)

    total_add = sum(1 for ch in plan.get("resource_changes", []) if "create" in ch["change"]["actions"])
    total_change = sum(1 for ch in plan.get("resource_changes", []) if "update" in ch["change"]["actions"])
    total_destroy = sum(1 for ch in plan.get("resource_changes", []) if "delete" in ch["change"]["actions"])

    md_output.append(f"**Plan Summary:** `{total_add} to add, {total_change} to change, {total_destroy} to destroy.`")

    return "\n".join(md_output)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process Terraform JSON plan into Markdown format.")
    parser.add_argument("json_path", help="Path to the Terraform JSON plan file")
    args = parser.parse_args()

    markdown_output = process_tf_plan(args.json_path)
    print(markdown_output)
