import collections
import logging
from typing import List, Tuple, Optional

from intezer_sdk.analysis import Analysis

logger = logging.getLogger(__name__)


def get_analysis_summary(analysis: Analysis, options: dict) -> str:
    result = analysis.result()
    metadata = analysis.get_root_analysis().metadata
    verdict = result['verdict'].lower()
    sub_verdict = result['sub_verdict'].lower()
    ignore_emojis = options.get('ignore_emojis', False)

    note = (f'Intezer Analyze File Scan\n'
            f'=========================\n\n')

    if verdict == 'malicious':
        emoji = get_emoji(verdict, ignore_emojis)
        main_family, gene_count = get_analysis_family(analysis, ['malware', 'malicious_packer'])
    elif verdict == 'trusted':
        emoji = get_emoji(verdict, ignore_emojis)
        main_family, gene_count = get_analysis_family(analysis, ['application', 'library', 'interpreter', 'installer'])
    elif verdict == 'suspicious':
        emoji = get_emoji(verdict, ignore_emojis)
        main_family, gene_count = get_analysis_family(analysis, ['administration_tool', 'packer'])
    else:
        emoji = get_emoji(verdict, ignore_emojis)
        main_family = None
        gene_count = None

    note = f'{note}{emoji} {verdict.capitalize()}'

    if verdict == 'suspicious' or verdict == 'unknown':
        note = f'{note} - {sub_verdict.replace("_", " ").title()}'
    if main_family:
        note = f'{note} - {main_family}'
        if gene_count:
            note = f'{note} ({gene_count} shared code genes)'
    note = f'{note}\n\nSize: {human_readable_size(metadata["size_in_bytes"])}\n'
    if 'file_type' in metadata:
        note = f'{note}File type: {metadata["file_type"]}\n'

    if verdict == 'malicious' or verdict == 'suspicious':
        iocs = len(analysis.iocs['files']) + len(analysis.iocs['network']) - 1

        if iocs:
            note = f'{note}IOCs: {iocs} IOCs\n'

        try:
            dynamic_ttps = len(analysis.dynamic_ttps)
        except Exception:
            logger.debug('no dynamic-ttps found related to analysis')
            dynamic_ttps = None

        if dynamic_ttps:
            note = f'{note}TTPs: {dynamic_ttps} techniques\n'

    note = (f'{note}\nFull report:\n'
            f'{get_emoji("result_url", ignore_emojis)} {result["analysis_url"]}')

    return note


def get_analysis_family(analysis: Analysis, software_type_priorities: List[str]) -> Tuple[Optional[str], Optional[int]]:
    result = analysis.result()
    family_name = result.get('family_name')
    if family_name:
        reused_gene_count = get_analysis_family_by_family_id(analysis, result['family_id'])
        return family_name, reused_gene_count

    largest_family_by_software_type = find_largest_family(analysis)
    for software_type in software_type_priorities:
        if software_type in largest_family_by_software_type:
            family = largest_family_by_software_type[software_type]
            return family['family_name'], family['reused_gene_count']

    return None, None


def get_analysis_family_by_family_id(analysis: Analysis, family_id: str) -> Optional[int]:
    reused_gene_count = 0

    for sub_analysis in analysis.get_sub_analyses():
        if not sub_analysis.code_reuse:
            continue

        for family in sub_analysis.code_reuse['families']:
            if family['family_id'] == family_id:
                if family['reused_gene_count'] > reused_gene_count:
                    reused_gene_count = family['reused_gene_count']

    return None if reused_gene_count == 0 else reused_gene_count


def find_largest_family(analysis: Analysis) -> dict:
    largest_family_by_software_type = collections.defaultdict(lambda: {'reused_gene_count': 0})
    for sub_analysis in analysis.get_sub_analyses():
        for family in sub_analysis.code_reuse['families']:
            software_type = family['family_type']
            if family['reused_gene_count'] > largest_family_by_software_type[software_type]['reused_gene_count']:
                largest_family_by_software_type[software_type] = family
    return largest_family_by_software_type


def human_readable_size(num: int) -> str:
    for unit in ['', 'KB', 'MB', 'GB']:
        if abs(num) < 1024.0:
            return f'{num:3.1f}{unit}'
        num /= 1024.0
    return f'{num:.1f}GB'


def get_emoji(key: str, ignore_emojis: bool = False):
    emojis_by_verdict = {
        'trusted': '✅',
        'malicious': '🧨',
        'suspicious': '⚠️',
        'unknown': '❔',
        'result_url': '👉'
    }

    return '' if ignore_emojis else emojis_by_verdict[key]
