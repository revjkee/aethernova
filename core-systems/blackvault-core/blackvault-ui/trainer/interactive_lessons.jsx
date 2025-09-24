import React, { useEffect, useState, useCallback } from "react";
import { Card, CardHeader, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Loader2, PlayCircle, CheckCircle2, AlertTriangle } from "lucide-react";
import { fetchLessonList, fetchLessonStep, submitLessonAnswer } from "@/lib/api/trainer";
import { cn } from "@/lib/utils";

export default function InteractiveLessons() {
  const [lessons, setLessons] = useState([]);
  const [selectedLesson, setSelectedLesson] = useState(null);
  const [currentStep, setCurrentStep] = useState(null);
  const [stepIndex, setStepIndex] = useState(0);
  const [loading, setLoading] = useState(false);
  const [completed, setCompleted] = useState(false);
  const [error, setError] = useState(null);

  const loadLessons = useCallback(async () => {
    try {
      const result = await fetchLessonList();
      setLessons(result);
    } catch (e) {
      setError("Ошибка загрузки уроков");
    }
  }, []);

  const startLesson = async (lessonId) => {
    setLoading(true);
    setError(null);
    setCompleted(false);
    setSelectedLesson(lessonId);
    try {
      const step = await fetchLessonStep(lessonId, 0);
      setCurrentStep(step);
      setStepIndex(0);
    } catch (e) {
      setError("Ошибка начала урока");
    } finally {
      setLoading(false);
    }
  };

  const nextStep = async () => {
    try {
      const next = await fetchLessonStep(selectedLesson, stepIndex + 1);
      setCurrentStep(next);
      setStepIndex((i) => i + 1);
    } catch (e) {
      setCompleted(true);
    }
  };

  const submitAnswer = async (payload) => {
    try {
      const response = await submitLessonAnswer(selectedLesson, stepIndex, payload);
      if (response.status === "ok") {
        nextStep();
      } else {
        setError("Ответ неверный или требует доработки");
      }
    } catch (e) {
      setError("Ошибка отправки ответа");
    }
  };

  useEffect(() => {
    loadLessons();
  }, [loadLessons]);

  return (
    <Card className="bg-zinc-900 text-white rounded-2xl shadow-2xl border border-slate-700">
      <CardHeader className="text-lg font-semibold">Интерактивные Уроки</CardHeader>
      <CardContent className="space-y-4">
        {!selectedLesson ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {lessons.map((lesson) => (
              <div key={lesson.id} className="p-4 bg-zinc-800 rounded-xl border border-slate-700">
                <div className="font-bold text-base">{lesson.title}</div>
                <div className="text-sm text-slate-400 mb-3">{lesson.description}</div>
                <Button
                  variant="default"
                  onClick={() => startLesson(lesson.id)}
                  disabled={loading}
                  className="w-full flex items-center gap-2"
                >
                  <PlayCircle className="w-4 h-4" />
                  Начать
                </Button>
              </div>
            ))}
          </div>
        ) : (
          <>
            {completed ? (
              <div className="text-green-400 flex items-center gap-2">
                <CheckCircle2 className="w-5 h-5" />
                Урок завершён. Отличная работа!
              </div>
            ) : (
              <>
                {currentStep && (
                  <div className="space-y-4">
                    <div className="text-base font-medium">{currentStep.title}</div>
                    <div className="text-sm text-slate-300">{currentStep.instruction}</div>
                    {/* Здесь может быть редактор кода, форма, тест и т.п. */}
                    <Button
                      onClick={() => submitAnswer({ answer: "ok" })}
                      className="bg-blue-600 hover:bg-blue-700 w-full mt-2"
                    >
                      Подтвердить
                    </Button>
                  </div>
                )}
                {error && (
                  <div className="text-red-400 flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4" />
                    {error}
                  </div>
                )}
              </>
            )}
          </>
        )}
        {loading && <Loader2 className="animate-spin w-6 h-6 text-slate-400" />}
      </CardContent>
    </Card>
  );
}
