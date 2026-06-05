#!/usr/bin/env python3
"""
Scanner Ingest CLI

Token setup (run once per platform):
  python cli.py token set --platform commercial
  python cli.py token set --platform fedramp

Quick test:
  python cli.py ingest tenable_sc --file scan.csv  --org <ORG_UID>
  python cli.py ingest tenable_sc --file scan.csv  --org <ORG_UID> --platform fedramp
  python cli.py ingest cisa       --file kev.csv   --org <ORG_UID>
  python cli.py ingest generic    --file out.json  --org <ORG_UID> --source my-scanner

Dry run (parse/validate only, no API calls):
  python cli.py ingest tenable_sc --file scan.csv --org <ORG_UID> --dry-run

Service mode:
  python cli.py serve --config config.yaml
"""
import logging
import os
import sys
from pathlib import Path

import click
import yaml
from dotenv import load_dotenv

from scanner_ingest import auth, pipeline
from scanner_ingest.adapters import ADAPTER_REGISTRY

load_dotenv()

_LOG_FORMAT  = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
_PLATFORM_CHOICES = click.Choice(list(auth.PLATFORMS), case_sensitive=False)


def _setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format=_LOG_FORMAT)
    logging.getLogger("apscheduler").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def _load_config(config_path: str) -> dict:
    path = Path(config_path)
    if not path.exists():
        click.echo(f"Config file not found: {config_path}", err=True)
        sys.exit(1)
    with open(path) as fh:
        return yaml.safe_load(fh) or {}


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------

@click.group()
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging.")
@click.pass_context
def cli(ctx: click.Context, verbose: bool):
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    _setup_logging(verbose)


# ---------------------------------------------------------------------------
# token group
# ---------------------------------------------------------------------------

@cli.group()
def token():
    """Manage Synack API tokens (stored in the OS keychain)."""


@token.command("set")
@click.option("--platform", "-p", type=_PLATFORM_CHOICES, default="commercial", show_default=True,
              help="Platform to store the token for.")
def token_set(platform: str):
    """Prompt for a Bearer token and store it in the OS keychain."""
    url = auth.platform_url(platform)
    click.echo(f"Platform : {platform}  ({url})")
    click.echo("Obtain your Bearer token from the Synack portal and paste it below.")
    value = click.prompt("Token", hide_input=True, confirmation_prompt=True)
    if not value.strip():
        click.secho("Aborted — empty token not stored.", fg="yellow")
        return
    auth.set_token(platform, value.strip())
    click.secho(f"✓ Token stored in keychain for platform '{platform}'.", fg="green")


@token.command("show")
@click.option("--platform", "-p", type=_PLATFORM_CHOICES, default=None,
              help="Platform to show (omit to show all).")
@click.option("--config", "-c", default="config.yaml", help="Path to config.yaml (for fallback lookup).")
def token_show(platform: str | None, config: str):
    """Show stored token status and source for one or both platforms."""
    cfg = _load_config(config) if Path(config).exists() else {}
    platforms = [platform] if platform else list(auth.PLATFORMS)

    for p in platforms:
        url    = auth.platform_url(p)
        tok    = auth.get_token(p, cfg)
        source = auth.token_source(p, cfg)
        masked = auth.mask_token(tok)
        status_color = "green" if tok else "red"
        click.secho(
            f"  {p:<12}  {url:<30}  {masked:<20}  [{source}]",
            fg=status_color,
        )


@token.command("clear")
@click.option("--platform", "-p", type=_PLATFORM_CHOICES, required=True,
              help="Platform whose token to remove from the keychain.")
def token_clear(platform: str):
    """Remove a stored token from the OS keychain."""
    click.confirm(f"Remove keychain token for '{platform}'?", abort=True)
    auth.delete_token(platform)
    click.secho(f"✓ Token cleared for platform '{platform}'.", fg="green")


# ---------------------------------------------------------------------------
# ingest command
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("source_type", type=click.Choice(list(ADAPTER_REGISTRY)), metavar="SOURCE")
@click.option("--file",        "-f", required=True,  type=click.Path(exists=True), help="Input file (.csv/.xlsx/.json)")
@click.option("--org",         "-o", default="",     help="Org UID — omit to auto-detect via assets API")
@click.option("--platform",    "-p", type=_PLATFORM_CHOICES, default="commercial", show_default=True,
              help="Target Synack platform.")
@click.option("--config",      "-c", default="config.yaml", help="Path to config.yaml")
@click.option("--source",      "-s", default=None,   help="Override source identifier sent to Synack")
@click.option("--listing-uid", default=None,         help="Synack listing UID to associate with all records")
@click.option("--asset-uid",   default=None,         help="Synack asset UID to associate with all records")
@click.option("--dry-run",     is_flag=True,         help="Parse and validate but do NOT submit to Synack")
@click.pass_context
def ingest(
    ctx: click.Context,
    source_type: str,
    file: str,
    org: str,
    platform: str,
    config: str,
    source: str | None,
    listing_uid: str | None,
    asset_uid: str | None,
    dry_run: bool,
):
    """Ingest a vulnerability file into Synack.

    SOURCE is one of: tenable_sc, cisa, qualys, generic
    """
    cfg = _load_config(config) if Path(config).exists() else {}

    if source:
        cfg.setdefault("sources", {}).setdefault(source_type, {})["source_id"] = source

    org_uid = org or os.getenv("SYNACK_ORG_UID") or cfg.get("synack", {}).get("organization_uid", "")

    click.echo(f"Platform : {platform}  ({auth.platform_url(platform)})")

    result = pipeline.run(
        file_path=Path(file),
        source_type=source_type,
        org_uid=org_uid,
        config=cfg,
        platform=platform,
        dry_run=dry_run,
        listing_uid=listing_uid,
        asset_uid=asset_uid,
    )

    _print_result(result, dry_run)
    sys.exit(0 if result.success else 1)


# ---------------------------------------------------------------------------
# serve command
# ---------------------------------------------------------------------------

@cli.command()
@click.option("--platform", "-p", type=_PLATFORM_CHOICES, default=None,
              help="Default platform for all watch dirs (overrides config.yaml).")
@click.option("--config", "-c", default="config.yaml", help="Path to config.yaml")
@click.pass_context
def serve(ctx: click.Context, platform: str | None, config: str):
    """Run as a service, watching directories for new files (configured in config.yaml)."""
    from scanner_ingest.scheduler import IngestScheduler

    cfg = _load_config(config)
    if platform:
        cfg.setdefault("synack", {})["platform"] = platform

    default_platform = cfg.get("synack", {}).get("platform", "commercial")
    click.echo(f"Default platform : {default_platform}  ({auth.platform_url(default_platform)})")
    click.echo("Starting ingest scheduler… (Ctrl-C to stop)")
    IngestScheduler(cfg).start()


# ---------------------------------------------------------------------------
# validate-config command
# ---------------------------------------------------------------------------

@cli.command("validate-config")
@click.option("--config", "-c", default="config.yaml", help="Path to config.yaml")
def validate_config(config: str):
    """Validate config.yaml and print effective settings (tokens masked)."""
    cfg    = _load_config(config) if Path(config).exists() else {}
    synack = cfg.get("synack", {})

    click.echo("=== Synack Platforms ===")
    for p, url in auth.PLATFORMS.items():
        tok    = auth.get_token(p, cfg)
        source = auth.token_source(p, cfg)
        masked = auth.mask_token(tok)
        color  = "green" if tok else "red"
        click.secho(f"  {p:<12}  {url:<30}  {masked:<20}  [{source}]", fg=color)

    default_platform = synack.get("platform", "commercial")
    click.echo(f"\n  default platform : {default_platform}")
    click.echo(f"  org_uid          : {synack.get('organization_uid') or os.getenv('SYNACK_ORG_UID') or '(not set)'}")
    click.echo(f"  batch_size       : {synack.get('batch_size', 100)}")

    click.echo("\n=== Sources ===")
    for src, vals in cfg.get("sources", {}).items():
        click.echo(f"  {src}: source_id={vals.get('source_id', src)}")

    click.echo("\n=== Scheduler ===")
    sched = cfg.get("scheduler", {})
    watch = sched.get("watch_dirs") or []
    click.echo(f"  poll_interval : {sched.get('poll_interval_seconds', 60)}s")
    click.echo(f"  watch_dirs    : {len(watch)} configured")
    for wd in watch:
        p = wd.get("platform", default_platform)
        click.echo(
            f"    {wd.get('path')} → source_type={wd.get('source_type')} "
            f"platform={p} org={wd.get('org_uid', '(env)')}"
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _print_result(result, dry_run: bool):
    tag = "[DRY RUN] " if dry_run else ""
    if result.success:
        click.secho(
            f"{tag}✓  {result.file.name}  parsed={result.parsed}  "
            f"submitted={result.submitted}  created_ids={result.created_ids or '(dry-run)'}",
            fg="green",
        )
    else:
        click.secho(f"{tag}✗  {result.file.name}", fg="red")
        for err in result.errors:
            click.secho(f"   {err}", fg="red")


if __name__ == "__main__":
    cli()
