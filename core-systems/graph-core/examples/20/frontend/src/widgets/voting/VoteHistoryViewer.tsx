import React, { useEffect, useState, useMemo } from 'react';
import { fetchVoteHistory } from '@/services/blockchain/voteLedger';
import { useZKIdentity } from '@/shared/hooks/useZKIdentity';
import { useAuditLogger } from '@/shared/hooks/useAuditLogger';
import { useNotification } from '@/shared/hooks/useNotification';
import { useDebounce } from '@/shared/hooks/useDebounce';
import { getProposalDetails } from '@/services/governance/proposalRegistry';
import { formatDateTime } from '@/utils/timeUtils';
import { RoleBadge } from '@/shared/components/RoleBadge';
import { ZKShield } from '@/shared/components/ZKShield';
import { truncateAddress } from '@/utils/formatters';
import { ExportCSV } from '@/shared/components/ExportCSV';
import { Loader } from '@/shared/components/Loader';
import { VoteRecord } from '@/types/governance';
import { VoteOutcomeIcon } from '@/shared/components/VoteOutcomeIcon';
import { Input } from '@/shared/components/Input';

type VoteHistoryViewerProps = {
  userAddress: string;
};

const VoteHistoryViewer: React.FC<VoteHistoryViewerProps> = ({ userAddress }) => {
  const [votes, setVotes] = useState<VoteRecord[]>([]);
  const [filteredVotes, setFilteredVotes] = useState<VoteRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [query, setQuery] = useState('');
  const debouncedQuery = useDebounce(query, 300);

  const { identityHash } = useZKIdentity(userAddress);
  const logAudit = useAuditLogger();
  const notify = useNotification();

  useEffect(() => {
    const loadHistory = async () => {
      try {
        setLoading(true);
        const result = await fetchVoteHistory(userAddress);
        const enriched = await Promise.all(
          result.map(async (vote) => {
            const proposal = await getProposalDetails(vote.proposalId);
            return {
              ...vote,
              proposalTitle: proposal.title,
              proposalCategory: proposal.category,
              delegateInfo: vote.delegatedFrom ? await fetchVoteHistory(vote.delegatedFrom) : null
            };
          })
        );
        setVotes(enriched);
        setFilteredVotes(enriched);
        logAudit({
          type: 'VIEW_VOTE_HISTORY',
          user: userAddress,
          identityHash,
          count: enriched.length
        });
      } catch (e) {
        console.error('Failed to load vote history', e);
        notify.error('Ошибка при загрузке истории голосований.');
        logAudit({
          type: 'VOTE_HISTORY_ERROR',
          user: userAddress,
          error: e.message
        });
      } finally {
        setLoading(false);
      }
    };

    loadHistory();
  }, [userAddress]);

  useEffect(() => {
    const q = debouncedQuery.toLowerCase();
    const filtered = votes.filter(
      (v) =>
        v.proposalTitle.toLowerCase().includes(q) ||
        v.proposalCategory.toLowerCase().includes(q) ||
        v.voteOption.toLowerCase().includes(q)
    );
    setFilteredVotes(filtered);
  }, [debouncedQuery, votes]);

  const csvData = useMemo(() => {
    return filteredVotes.map((v) => ({
      Proposal: v.proposalTitle,
      Category: v.proposalCategory,
      Vote: v.voteOption,
      Weight: v.weight,
      DelegatedFrom: v.delegatedFrom ? truncateAddress(v.delegatedFrom) : 'Self',
      Date: formatDateTime(v.timestamp)
    }));
  }, [filteredVotes]);

  if (loading) {
    return <Loader label="Загрузка истории голосований..." />;
  }

  return (
    <div className="bg-white dark:bg-gray-900 p-6 border rounded-md shadow-sm">
      <h3 className="text-lg font-bold mb-4 text-gray-800 dark:text-white">История голосований</h3>

      <div className="mb-4 flex justify-between items-center">
        <Input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Поиск по заголовку, категории или голосу..."
          className="w-2/3"
        />
        <ExportCSV data={csvData} filename={`vote_history_${userAddress}.csv`} />
      </div>

      {filteredVotes.length === 0 ? (
        <div className="text-gray-500 italic">Нет голосований по текущим фильтрам.</div>
      ) : (
        <table className="w-full text-sm text-left">
          <thead>
            <tr className="text-gray-600 dark:text-gray-300">
              <th>Предложение</th>
              <th>Категория</th>
              <th>Голос</th>
              <th>Вес</th>
              <th>Делегат</th>
              <th>Дата</th>
              <th>ZK</th>
            </tr>
          </thead>
          <tbody>
            {filteredVotes.map((v, idx) => (
              <tr key={idx} className="border-t border-gray-200 dark:border-gray-700">
                <td className="py-2">{v.proposalTitle}</td>
                <td>{v.proposalCategory}</td>
                <td><VoteOutcomeIcon option={v.voteOption} /> {v.voteOption}</td>
                <td>{v.weight.toFixed(2)}</td>
                <td>{v.delegatedFrom ? truncateAddress(v.delegatedFrom) : <span className="text-green-600">Вы</span>}</td>
                <td>{formatDateTime(v.timestamp)}</td>
                <td><ZKShield zkProof={v.zkProof} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
};

export default VoteHistoryViewer;
