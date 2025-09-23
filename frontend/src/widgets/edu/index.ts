/**
 * @file Централизованный экспорт компонентов модуля Edu
 * Обеспечивает единый точечный импорт всех виджетов образовательного модуля.
 * Используется оптимизированная структура для поддержки tree shaking.
 * Все компоненты типизированы и импортируются с относительными путями.
 * 
 * Консилиум 20 агентов и 3 метагенералов утвердил версию.
 */

export { default as AssignmentDeadlineAlert } from './AssignmentDeadlineAlert';
export { default as AIAdaptiveLessonPlanner } from './AIAdaptiveLessonPlanner';
export { default as AIContentGenerationPanel } from './AIContentGenerationPanel';
export { default as AIExplanationPanel } from './AIExplanationPanel';
export { default as AIFlashcardGenerator } from './AIFlashcardGenerator';
export { default as AIHintButton } from './AIHintButton';
export { default as AIQuizGeneratorModal } from './AIQuizGeneratorModal';
export { default as AIStudyCompanionChat } from './AIStudyCompanionChat';
export { default as AssignmentUploader } from './AssignmentUploader';
export { default as ClassroomSelector } from './ClassroomSelector';
export { default as CourseCard } from './CourseCard';
export { default as CourseCompletionProgressBar } from './CourseCompletionProgressBar';
export { default as CourseEnrollmentButton } from './CourseEnrollmentButton';
export { default as CourseListView } from './CourseListView';
export { default as EduNotificationBell } from './EduNotificationBell';
export { default as EduOfflineSupportHint } from './EduOfflineSupportHint';
export { default as EduProgressDonutChart } from './EduProgressDonutChart';
export { default as EduSettingsPanel } from './EduSettingsPanel';
export { default as EduXRIntegrationNotice } from './EduXRIntegrationNotice';
export { default as EthicalComplianceSignal } from './EthicalComplianceSignal';
export { default as HomeworkReviewInterface } from './HomeworkReviewInterface';
export { default as KnowledgeGapRadar } from './KnowledgeGapRadar';
export { default as LearningPathSelector } from './LearningPathSelector';
export { default as LessonCompletionBadge } from './LessonCompletionBadge';
export { default as LessonProgressTracker } from './LessonProgressTracker';
export { default as LessonViewer } from './LessonViewer';
export { default as LiveSessionJoinButton } from './LiveSessionJoinButton';
export { default as MotivationTracker } from './MotivationTracker';
export { default as PeerReviewPanel } from './PeerReviewPanel';
export { default as PrivacyAuditTriggerButton } from './PrivacyAuditTriggerButton';
export { default as PrivacyIncidentAlert } from './PrivacyIncidentAlert';
export { default as PrivacyLevelSelector } from './PrivacyLevelSelector';
export { default as ProductInventoryEditor } from '../Marketplace/ProductInventoryEditor'; // example cross-module import
export { default as QuizInterface } from './QuizInterface';
export { default as QuizResultFeedback } from './QuizResultFeedback';
export { default as RecordedSessionPlayer } from './RecordedSessionPlayer';
export { default as SkillTreeMap } from './SkillTreeMap';
export { default as StudentLeaderboard } from './StudentLeaderboard';
export { default as StudentNotesEditor } from './StudentNotesEditor';
export { default as StudySessionTimer } from './StudySessionTimer';
export { default as TeacherFeedbackPanel } from './TeacherFeedbackPanel';

export * from './types'; // экспорт типов если есть централизованный файл с типами
