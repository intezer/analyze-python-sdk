import collections
from typing import List
from typing import Optional
from typing import Tuple

from intezer_sdk.analysis import Analysis

emojis_by_key = {
    'trusted': '✅',
    'malicious': '🧨',
    'suspicious': '⚠️',
    'unknown': '❔',
    'result_url': '👉'
}


def get_analysis_summary(analysis: Analysis, no_emojis: bool=False) -> str:
    result = analysis.result()

    metadata = analysis.get_root_analysis().metadata
    verdict = result['verdict'].lower()
    sub_verdict = result['sub_verdict'].lower()
    emoji = ''

    note = (f'Intezer Analyze File Scan\n'
            f'=========================\n\n')

    if not no_emojis:
        emoji = get_emoji(verdict)

    if verdict == 'malicious':
        main_family, gene_count = get_analysis_family(analysis, ['malware', 'malicious_packer'])
    elif verdict == 'trusted':
        main_family, gene_count = get_analysis_family(analysis, ['application', 'library', 'interpreter', 'installer'])
    elif verdict == 'suspicious':
        main_family, gene_count = get_analysis_family(analysis, ['administration_tool', 'packer'])
    else:
        main_family = None
        gene_count = None

    note = f'{note}{emoji} {verdict.capitalize()}'

    if verdict in ('suspicious', 'unknown'):
        note = f'{note} - {sub_verdict.replace("_", " ").title()}'
    if main_family:
        note = f'{note} - {main_family}'
        if gene_count:
            note = f'{note} ({gene_count} shared code genes)'
    note = f'{note}\n\nSize: {human_readable_size(metadata["size_in_bytes"])}\n'

    if 'file_type' in metadata:
        note = f'{note}File type: {metadata["file_type"]}\n'

    if verdict in ('malicious', 'suspicious'):
        iocs = analysis.iocs

        if iocs:
            iocs_count = 0
            files = iocs.get('files')
            network = iocs.get('network')

            if files:
                iocs_count += len(files)

            if network:
                iocs_count += len(network)

            if iocs_count > 1:
                note = f'{note}IOCs: {iocs_count} IOCs\n'

        if analysis.dynamic_ttps:
            note = f'{note}TTPs: {len(analysis.dynamic_ttps)} techniques\n'

    note = (f'{note}\nFull report:\n'
            f'{"" if no_emojis else get_emoji("result_url")} {result["analysis_url"]}')

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


def get_analysis_family_by_family_id(analysis: Analysis, family_id: str) -> int:
    reused_gene_count = 0

    for sub_analysis in analysis.get_sub_analyses():
        if not sub_analysis.code_reuse:
            continue

        for family in sub_analysis.code_reuse['families']:
            if family['family_id'] == family_id:
                if family['reused_gene_count'] > reused_gene_count:
                    reused_gene_count = family['reused_gene_count']

    return reused_gene_count


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


def get_emoji(key: str):
    return emojis_by_key[key]
