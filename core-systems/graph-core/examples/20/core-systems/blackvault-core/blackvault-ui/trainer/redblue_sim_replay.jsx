import React, { useEffect, useState } from "react";
import { Card, CardHeader, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Select, SelectTrigger, SelectValue, SelectContent, SelectItem } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import { fetchReplaysList, fetchReplayFrame } from "@/lib/api/simulation";
import { PauseCircle, PlayCircle, RotateCcw, ShieldAlert, TerminalSquare } from "lucide-react";

export default function RedBlueSimReplay() {
  const [replays, setReplays] = useState([]);
  const [selectedReplayId, setSelectedReplayId] = useState(null);
  const [frames, setFrames] = useState([]);
  const [currentFrame, setCurrentFrame] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    fetchReplaysList()
      .then(setReplays)
      .catch(() => setError("Ошибка загрузки списка реплеев"));
  }, []);

  useEffect(() => {
    if (!selectedReplayId) return;
    setLoading(true);
    fetchReplayFrame(selectedReplayId)
      .then((data) => {
        setFrames(data.frames);
        setCurrentFrame(0);
      })
      .catch(() => setError("Ошибка загрузки данных симуляции"))
      .finally(() => setLoading(false));
  }, [selectedReplayId]);

  useEffect(() => {
    if (!playing || !frames.length) return;
    const interval = setInterval(() => {
      setCurrentFrame((prev) => {
        if (prev + 1 >= frames.length) {
          setPlaying(false);
          return prev;
        }
        return prev + 1;
      });
    }, 1200);
    return () => clearInterval(interval);
  }, [playing, frames]);

  const handleReplaySelect = (value) => {
    setSelectedReplayId(value);
    setPlaying(false);
  };

  const handleRestart = () => {
    setCurrentFrame(0);
    setPlaying(true);
  };

  const frame = frames[currentFrame] || {};

  return (
    <Card className="bg-black border border-slate-700 rounded-2xl shadow-2xl text-white">
      <CardHeader className="text-xl font-bold">Симуляция Red vs Blue</CardHeader>
      <CardContent className="space-y-4">
        <Select onValueChange={handleReplaySelect}>
          <SelectTrigger className="w-full bg-zinc-800 border-slate-600">
            <SelectValue placeholder="Выберите реплей..." />
          </SelectTrigger>
          <SelectContent>
            {replays.map((r) => (
              <SelectItem key={r.id} value={r.id}>
                {r.name} — {r.date}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        {selectedReplayId && (
          <>
            <div className="flex justify-between items-center text-sm text-slate-300">
              <span>Кадр {currentFrame + 1} / {frames.length}</span>
              <Progress value={(currentFrame + 1) * 100 / frames.length} className="w-2/3" />
            </div>

            <div className="p-4 border border-slate-600 bg-zinc-900 rounded-xl space-y-2">
              <div className="text-base font-semibold text-sky-400">Red Team:</div>
              <ul className="list-disc ml-5 text-sm text-red-400">
                {frame.red_actions?.map((action, idx) => (
                  <li key={idx}>{action}</li>
                )) || <li>—</li>}
              </ul>

              <div className="text-base font-semibold text-emerald-400 mt-3">Blue Team:</div>
              <ul className="list-disc ml-5 text-sm text-emerald-400">
                {frame.blue_responses?.map((resp, idx) => (
                  <li key={idx}>{resp}</li>
                )) || <li>—</li>}
              </ul>

              <div className="text-base mt-3 font-semibold text-yellow-400">Системы под угрозой:</div>
              <ul className="list-disc ml-5 text-sm text-yellow-300">
                {frame.threatened_systems?.map((sys, idx) => (
                  <li key={idx}>{sys}</li>
                )) || <li>—</li>}
              </ul>
            </div>

            <div className="flex gap-3 mt-4 justify-center">
              <Button variant="ghost" onClick={() => setPlaying(!playing)}>
                {playing ? <PauseCircle className="w-5 h-5 text-slate-300" /> : <PlayCircle className="w-5 h-5 text-green-400" />}
              </Button>
              <Button variant="ghost" onClick={handleRestart}>
                <RotateCcw className="w-5 h-5 text-blue-400" />
              </Button>
            </div>
          </>
        )}

        {error && (
          <div className="text-red-400 text-sm mt-2 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4" />
            {error}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
