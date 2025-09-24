// path: src/pages/StudentTracker.tsx

import { useEffect, useState, useMemo, useCallback } from "react";
import { useAuth } from "@/features/auth/hooks/useAuth";
import { useStudentProgressQuery, useStudentStream } from "@/features/education/studentAPI";
import { StudentRow } from "@/features/education/components/StudentRow";
import { FilterPanel } from "@/features/education/components/FilterPanel";
import { Spinner } from "@/shared/components/Spinner";
import { Modal } from "@/shared/components/Modal";
import { StudentDetailPanel } from "@/features/education/components/StudentDetailPanel";
import { useDebounce } from "@/shared/hooks/useDebounce";
import { Helmet } from "react-helmet";
import { AnimatePresence, motion } from "framer-motion";
import { AccessGuard } from "@/shared/components/AccessGuard";
import { ROLE } from "@/shared/constants/roles";
import { toast } from "react-toastify";
import { exportStudentAuditCSV } from "@/features/audit/auditExporter";
import { Button } from "@/shared/components/Button";
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import { ZKProofBadge } from "@/shared/components/ZKProofBadge";

const StudentTracker = () => {
  const { user, isAuthenticated } = useAuth();
  const [search, setSearch] = useState("");
  const debouncedSearch = useDebounce(search, 400);

  const [selectedStudentId, setSelectedStudentId] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);

  const { data: students, isLoading, refetch } = useStudentProgressQuery({ search: debouncedSearch });
  const { stream, subscribe, unsubscribe } = useStudentStream();

  useEffect(() => {
    if (selectedStudentId) subscribe(selectedStudentId);
    return () => unsubscribe(selectedStudentId);
  }, [selectedStudentId]);

  const filteredStudents = useMemo(() => {
    if (!students) return [];
    return students.filter((s) => s.name.toLowerCase().includes(debouncedSearch.toLowerCase()));
  }, [students, debouncedSearch]);

  const handleOpenStudent = useCallback((id: string) => {
    setSelectedStudentId(id);
    setModalOpen(true);
  }, []);

  const handleExport = async () => {
    try {
      await exportStudentAuditCSV();
      toast.success("Экспорт завершён");
    } catch {
      toast.error("Ошибка при экспорте");
    }
  };

  return (
    <AccessGuard roles={[ROLE.ADMIN, ROLE.INSTRUCTOR]}>
      <Helmet>
        <title>Трекинг студентов | NeuroCity</title>
        <meta name="description" content="Отслеживание прогресса, AI-предсказания, активности и аномалий студентов" />
      </Helmet>

      <div className="px-6 py-8 min-h-screen">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-3xl font-semibold">Трекинг студентов</h1>
          <Button onClick={handleExport}>Экспорт CSV</Button>
        </div>

        <div className="flex flex-col lg:flex-row gap-6">
          <aside className="w-full lg:w-1/4">
            <FilterPanel
              filters={{ search }}
              onChange={({ search }) => setSearch(search)}
              placeholder="Поиск студента..."
            />
          </aside>

          <main className="w-full lg:w-3/4">
            {isLoading ? (
              <div className="flex justify-center items-center h-[200px]">
                <Spinner />
              </div>
            ) : (
              <table className="min-w-full border">
                <thead>
                  <tr className="bg-gray-100 text-left text-sm font-semibold">
                    <th className="px-4 py-2">ID</th>
                    <th className="px-4 py-2">Имя</th>
                    <th className="px-4 py-2">Прогресс (%)</th>
                    <th className="px-4 py-2">Последняя активность</th>
                    <th className="px-4 py-2">AI-предсказание</th>
                    <th className="px-4 py-2">ZK-валид.</th>
                    <th className="px-4 py-2">Подробнее</th>
                  </tr>
                </thead>
                <tbody>
                  <AnimatePresence initial={false}>
                    {filteredStudents.map((student) => (
                      <motion.tr
                        key={student.id}
                        layout
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        transition={{ duration: 0.2 }}
                      >
                        <StudentRow
                          student={student}
                          onOpenDetails={() => handleOpenStudent(student.id)}
                          stream={stream}
                        />
                      </motion.tr>
                    ))}
                  </AnimatePresence>
                </tbody>
              </table>
            )}
          </main>
        </div>

        <AnimatePresence>
          {modalOpen && selectedStudentId && (
            <Modal onClose={() => setModalOpen(false)}>
              <StudentDetailPanel studentId={selectedStudentId} />
            </Modal>
          )}
        </AnimatePresence>

        <div className="mt-10 bg-white dark:bg-zinc-900 p-6 rounded-lg shadow-md">
          <h2 className="text-xl font-medium mb-4">AI-прогноз успеваемости</h2>
          <ResponsiveContainer width="100%" height={280}>
            <LineChart data={students?.slice(0, 10).map(s => ({ name: s.name, progress: s.aiPrediction })) || []}>
              <XAxis dataKey="name" />
              <YAxis />
              <Tooltip />
              <Line type="monotone" dataKey="progress" stroke="#8884d8" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </AccessGuard>
  );
};

export default StudentTracker;
