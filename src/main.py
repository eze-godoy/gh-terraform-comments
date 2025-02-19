import json
import argparse
import os
import requests
import logging

# Configure logging
logger = logging.getLogger()
log_level = os.environ.get('log_level', 'DEBUG').upper()
logger.setLevel(getattr(logging, log_level, logging.INFO))

def format_create_or_delete(resource, prefix):
    """Formats a full resource with '+' for create or '-' for delete."""
    lines = ["```diff"]
    def recursive_format(data, indent=0):
        spaces = " " * indent
        if isinstance(data, dict):
            for key, value in data.items():
                lines.append(f'{prefix} {spaces}"{key}": {{')
                recursive_format(value, indent + 2)
                lines.append(f"{spaces}}},")
        elif isinstance(data, list):
            lines.append(f"{prefix} {spaces}[")
            for item in data:
                recursive_format(item, indent + 2)
            lines.append(f"{spaces}],")
        else:
            lines.append(f"{prefix} {spaces}{json.dumps(data)},")
    
    recursive_format(resource)
    lines.append("```")
    return "\n".join(lines)

def format_update(before, after):
    """Formats only changed attributes in an update."""
    diff_lines = ["```diff"]

    def recursive_diff(before, after, indent=0):
        spaces = " " * indent

        if isinstance(before, dict) and isinstance(after, dict):
            for key in before.keys() | after.keys():
                if key not in before:
                    diff_lines.append(f'{spaces}+ "{key}": {json.dumps(after[key], indent=2)},')
                elif key not in after:
                    diff_lines.append(f'{spaces}- "{key}": {json.dumps(before[key], indent=2)},')
                elif before[key] != after[key]:
                    diff_lines.append(f'{spaces}"{key}": [')
                    recursive_diff(before[key], after[key], indent + 2)
                    diff_lines.append(f"{spaces}],")

        elif isinstance(before, list) and isinstance(after, list):
            if all(isinstance(item, str) for item in before + after):
                removed = set(before) - set(after)
                added = set(after) - set(before)
                for item in removed:
                    diff_lines.append(f'- {spaces}"{item}",')
                for item in added:
                    diff_lines.append(f'+ {spaces}"{item}",')
            elif all(isinstance(item, dict) for item in before + after):
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

    total_add = sum(1 for ch in plan.get("resource_changes", []) if "create" in ch["change"]["actions"])
    total_change = sum(1 for ch in plan.get("resource_changes", []) if "update" in ch["change"]["actions"])
    total_destroy = sum(1 for ch in plan.get("resource_changes", []) if "delete" in ch["change"]["actions"])

    summary = f"**Plan Summary:** `{total_add} to add, {total_change} to change, {total_destroy} to destroy.`\n"
    
    create_section, update_section, delete_section = [], [], []

    for change in plan.get("resource_changes", []):
        actions = change["change"]["actions"]
        address = change['address']

        if "create" in actions:
            create_section.append(f"### `{address}` will be **created**\n")
            create_section.append(format_create_or_delete(change["change"]["after"], "+"))

        if "delete" in actions:
            delete_section.append(f"### `{address}` will be **deleted**\n")
            delete_section.append(format_create_or_delete(change["change"]["before"], "-"))

        if "update" in actions:
            update_section.append(f"### `{address}` will be **updated**\n")
            update_section.append(format_update(change["change"]["before"], change["change"]["after"]))

    md_output = [summary]

    if create_section:
        md_output.append("## 🚀 Resources to be Created\n" + "\n".join(create_section))
    if delete_section:
        md_output.append("## 🗑️ Resources to be Deleted\n" + "\n".join(delete_section))
    if update_section:
        md_output.append("## 🔄 Resources to be Updated\n" + "\n".join(update_section))

    return "\n".join(md_output)

def post_to_github_pr(comment):
    """Posts a comment to a GitHub Pull Request using GitHub Actions environment variables."""
    github_token = os.getenv("GITHUB_TOKEN")
    repo = os.getenv("GITHUB_REPOSITORY")  # e.g., "user/repo"
    pr_number = os.getenv("GITHUB_PR_NUMBER")  # If set manually

    if not pr_number:  # Automatically get PR number from GitHub Actions
        event_path = os.getenv("GITHUB_EVENT_PATH")
        if event_path and os.path.exists(event_path):
            with open(event_path, "r") as f:
                event_data = json.load(f)
                pr_number = event_data.get("pull_request", {}).get("number")

    if not github_token or not repo or not pr_number:
        print("❌ Missing required environment variables (GITHUB_TOKEN, GITHUB_REPOSITORY, or PR number)")
        return

    logger.info("Posting comment to GitHub PR", extras={"repo": repo, "pr_number": pr_number})

    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {"Authorization": f"token {github_token}", "Accept": "application/vnd.github.v3+json"}
    data = json.dumps({"body": comment})

    response = requests.post(url, headers=headers, data=data)

    if response.status_code == 201:
        print("✅ Comment posted successfully!")
    else:
        print(f"❌ Failed to post comment: {response.status_code}, Response: {response.text}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process Terraform JSON plan and post results to GitHub PR.")
    parser.add_argument("json_path", help="Path to the Terraform JSON plan file")
    args = parser.parse_args()

    markdown_output = process_tf_plan(args.json_path)
    post_to_github_pr(markdown_output)
