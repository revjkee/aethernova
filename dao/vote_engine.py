# dao/vote_engine.py

from typing import Dict, Optional
from datetime import datetime

class VoteEngine:
    def __init__(self, proposals: Dict[str, dict]):
        """
        proposals: словарь с proposal_id в качестве ключа и данными предложений как значением
        """
        self.proposals = proposals

    def tally_votes(self, proposal_id: str) -> Optional[Dict[str, int]]:
        """
        Подсчёт голосов по предложению.
        Возвращает словарь с количеством голосов 'for', 'against', 'abstain' или None, если proposal_id не найден.
        """
        proposal = self.proposals.get(proposal_id)
        if not proposal:
            return None

        votes = proposal.get('votes', {})
        return {
            'for': votes.get('for', 0),
            'against': votes.get('against', 0),
            'abstain': votes.get('abstain', 0)
        }

    def is_quorum_reached(self, proposal_id: str, quorum_threshold: int) -> bool:
        """
        Проверка достижения кворума по предложению.
        quorum_threshold — минимальное количество голосов для достижения кворума.
        """
        votes = self.tally_votes(proposal_id)
        if votes is None:
            return False

        total_votes = votes['for'] + votes['against'] + votes['abstain']
        return total_votes >= quorum_threshold

    def get_voting_status(self, proposal_id: str) -> Optional[str]:
        """
        Определение статуса голосования: 'pending', 'active', 'finished', 'invalid' или None, если предложение не найдено.
        """
        proposal = self.proposals.get(proposal_id)
        if not proposal:
            return None

        now_ts = int(datetime.utcnow().timestamp())
        start_ts = proposal.get('voting_start_timestamp')
        end_ts = proposal.get('voting_end_timestamp')

        if now_ts < start_ts:
            return 'pending'
        elif start_ts <= now_ts <= end_ts:
            return 'active'
        elif now_ts > end_ts:
            return 'finished'
        else:
            return 'invalid'

    def compute_result(self, proposal_id: str) -> Optional[str]:
        """
        Вычисляет результат голосования:
        'approved' если 'for' > 'against' и кворум достигнут,
        'rejected' если 'against' >= 'for' или кворум не достигнут,
        или None если предложение не найдено.
        """
        proposal = self.proposals.get(proposal_id)
        if not proposal:
            return None

        votes = self.tally_votes(proposal_id)
        if not votes:
            return None

        quorum_reached = proposal.get('quorum_reached', False)

        if not quorum_reached:
            return 'rejected'

        if votes['for'] > votes['against']:
            return 'approved'
        else:
            return 'rejected'

    def update_proposal_result(self, proposal_id: str):
        """
        Обновляет поле result в предложении на основе вычисленного результата.
        """
        result = self.compute_result(proposal_id)
        if result and proposal_id in self.proposals:
            self.proposals[proposal_id]['result'] = result

