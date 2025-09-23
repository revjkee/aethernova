// src/widgets/Governance/ZKVoteVerifier.tsx

import React, { useEffect, useState, Suspense } from 'react';
import { Card, CardHeader, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Progress } from '@/components/ui/progress';
import { AlertCircle, ShieldCheck, ShieldX } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useZKVerifier } from '@/hooks/zk/useZKVerifier';
import { decodeZKProof, verifyProofHash } from '@/lib/zk/zkUtils';
import { Skeleton } from '@/components/ui/skeleton';

type VoteZKProof = {
  voterIdHash: string;         // хеш идентификатора голосующего
  voteHash: string;            // хеш голоса
  proof: string;               // zk-snark proof string (base64)
  timestamp: number;          // время голосования
  signature: string;          // подпись (опционально)
};

interface ZKVoteVerifierProps {
  voteProof: VoteZKProof;
  expectedVoteHash: string;
  expectedVoterIdHash?: string;
}

const ZKVoteVerifier: React.FC<ZKVoteVerifierProps> = ({
  voteProof,
  expectedVoteHash,
  expectedVoterIdHash,
}) => {
  const [verifying, setVerifying] = useState<boolean>(true);
  const [isValid, setIsValid] = useState<boolean | null>(null);
  const [details, setDetails] = useState<any>(null);
  const zk = useZKVerifier();

  useEffect(() => {
    const runVerification = async () => {
      setVerifying(true);
      try {
        const decoded = decodeZKProof(voteProof.proof);
        const verified = await zk.verify({
          proof: voteProof.proof,
          publicSignals: {
            voteHash: voteProof.voteHash,
            voterIdHash: voteProof.voterIdHash,
          },
        });

        const hashMatches = verifyProofHash(voteProof.voteHash, expectedVoteHash);
        const voterMatch =
          expectedVoterIdHash === undefined ||
          verifyProofHash(voteProof.voterIdHash, expectedVoterIdHash);

        setIsValid(verified && hashMatches && voterMatch);
        setDetails({
          hashValid: hashMatches,
          voterMatch,
          decoded,
        });
      } catch (err) {
        console.error('ZK Verification error:', err);
        setIsValid(false);
      } finally {
        setVerifying(false);
      }
    };

    runVerification();
  }, [voteProof, expectedVoteHash, expectedVoterIdHash]);

  const renderStatus = () => {
    if (verifying) {
      return (
        <div className="flex items-center gap-3">
          <Skeleton className="w-8 h-8 rounded-full" />
          <span>Проверка доказательства...</span>
        </div>
      );
    }

    if (isValid === true) {
      return (
        <div className="flex items-center gap-3 text-green-600 font-semibold">
          <ShieldCheck className="w-6 h-6" />
          Доказательство подлинно
        </div>
      );
    }

    if (isValid === false) {
      return (
        <div className="flex items-center gap-3 text-red-600 font-semibold">
          <ShieldX className="w-6 h-6" />
          Доказательство не прошло проверку
        </div>
      );
    }

    return (
      <div className="flex items-center gap-3 text-muted-foreground">
        <AlertCircle className="w-5 h-5" />
        Статус неизвестен
      </div>
    );
  };

  return (
    <Card className="bg-white/5 border border-border/30 shadow-inner p-4 max-w-xl">
      <CardHeader>
        <div className="text-lg font-bold">ZK-Проверка голоса</div>
        <div className="text-muted-foreground text-sm">Zero-Knowledge Proof верификация</div>
      </CardHeader>
      <CardContent className="space-y-4">
        {renderStatus()}

        {!verifying && isValid !== null && (
          <>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div>
                <span className="text-muted-foreground">Хеш голоса:</span>
                <div className={cn("truncate", details?.hashValid ? "text-green-400" : "text-red-400")}>
                  {voteProof.voteHash}
                </div>
              </div>
              <div>
                <span className="text-muted-foreground">Хеш голосующего:</span>
                <div className={cn("truncate", details?.voterMatch ? "text-green-400" : "text-red-400")}>
                  {voteProof.voterIdHash}
                </div>
              </div>
            </div>

            <Progress
              value={isValid ? 100 : 0}
              className={cn("h-2 transition-all", isValid ? "bg-green-600" : "bg-red-600")}
            />
            <div className="text-xs text-muted-foreground">
              Время: {new Date(voteProof.timestamp).toLocaleString()}
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
};

export default ZKVoteVerifier;
