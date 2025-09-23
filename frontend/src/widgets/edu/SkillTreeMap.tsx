import React, { useEffect, useRef, useState, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import * as d3 from 'd3';
import { fetchSkillTreeData, updateSkillProgress } from '@/services/api/skillTreeAPI';
import { Spinner } from '@/shared/components/Spinner';
import { cn } from '@/shared/utils/cn';

interface SkillNode {
  id: string;
  name: string;
  description?: string;
  children?: SkillNode[];
  progress: number; // 0-100%
  iconUrl?: string;
}

interface Props {
  userId: string;
  courseId: string;
  className?: string;
}

const SkillTreeMap: React.FC<Props> = ({ userId, courseId, className }) => {
  const { t } = useTranslation();
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [skillTree, setSkillTree] = useState<SkillNode | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedSkill, setSelectedSkill] = useState<SkillNode | null>(null);

  // Загрузка данных дерева навыков
  useEffect(() => {
    let cancelled = false;
    const loadData = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await fetchSkillTreeData(userId, courseId);
        if (!cancelled) setSkillTree(data);
      } catch {
        if (!cancelled) setError(t('edu.skillTree.loadError'));
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    loadData();
    return () => {
      cancelled = true;
    };
  }, [userId, courseId, t]);

  // Инициализация D3 дерева
  const initializeTree = useCallback(() => {
    if (!skillTree || !svgRef.current) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const width = svgRef.current.clientWidth;
    const height = svgRef.current.clientHeight;

    const root = d3.hierarchy<SkillNode>(skillTree, (d) => d.children);
    const treeLayout = d3.tree<SkillNode>().size([height, width - 200]);
    treeLayout(root);

    // Группы для ссылок и узлов
    const gLinks = svg.append('g').attr('fill', 'none').attr('stroke', '#ccc').attr('stroke-width', 2);
    const gNodes = svg.append('g').attr('cursor', 'pointer');

    // Ссылки
    gLinks
      .selectAll('path')
      .data(root.links())
      .join('path')
      .attr('d', d3.linkHorizontal()
        .x(d => d.y)
        .y(d => d.x) as any)
      .attr('stroke', '#aaa');

    // Узлы
    const nodeGroups = gNodes
      .selectAll('g')
      .data(root.descendants())
      .join('g')
      .attr('transform', (d) => `translate(${d.y},${d.x})`)
      .on('click', (event, d) => {
        setSelectedSkill(d.data);
      })
      .attr('tabindex', 0)
      .attr('role', 'button')
      .attr('aria-label', (d) => `${d.data.name}, ${t('edu.skillTree.progress')}: ${d.data.progress}%`)
      .on('keydown', (event, d) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          setSelectedSkill(d.data);
        }
      });

    // Круг с прогрессом
    nodeGroups
      .append('circle')
      .attr('r', 20)
      .attr('fill', '#f3f4f6')
      .attr('stroke', '#6b7280')
      .attr('stroke-width', 2);

    // Прогресс кольцо
    const arc = d3.arc()
      .innerRadius(22)
      .outerRadius(26)
      .startAngle(0)
      .endAngle((d: any) => (d.data.progress / 100) * 2 * Math.PI);

    nodeGroups
      .append('path')
      .attr('d', arc as any)
      .attr('fill', '#3b82f6');

    // Иконки (если есть)
    nodeGroups
      .filter(d => d.data.iconUrl)
      .append('image')
      .attr('href', d => d.data.iconUrl!)
      .attr('x', -12)
      .attr('y', -12)
      .attr('width', 24)
      .attr('height', 24);

    // Названия навыков
    nodeGroups
      .append('text')
      .attr('dy', 5)
      .attr('x', 30)
      .attr('fill', '#374151')
      .style('font-weight', '600')
      .text(d => d.data.name)
      .call((text) => text.each(function() {
        const el = d3.select(this);
        const words = el.text().split(' ');
        if (words.length > 3) {
          el.text(words.slice(0, 3).join(' ') + '...');
        }
      }));

  }, [skillTree, t]);

  useEffect(() => {
    initializeTree();
  }, [skillTree, initializeTree]);

  const handleProgressChange = useCallback(async (skillId: string, newProgress: number) => {
    if (!skillTree) return;
    try {
      await updateSkillProgress(userId, courseId, skillId, newProgress);
      // Обновить локально для отзывчивости
      setSkillTree((prev) => {
        if (!prev) return prev;

        const updateNodeProgress = (node: SkillNode): SkillNode => {
          if (node.id === skillId) {
            return { ...node, progress: newProgress };
          }
          if (node.children) {
            return { ...node, children: node.children.map(updateNodeProgress) };
          }
          return node;
        };

        return updateNodeProgress(prev);
      });
    } catch {
      // Игнорируем ошибки на UI, но можно показывать уведомление
    }
  }, [userId, courseId, skillTree]);

  return (
    <section
      aria-label={t('edu.skillTree.ariaLabel')}
      className={cn('relative w-full h-[600px] bg-white dark:bg-zinc-900 rounded-md shadow-md', className)}
      tabIndex={0}
    >
      {loading && (
        <div className="absolute inset-0 flex items-center justify-center bg-white bg-opacity-80 dark:bg-zinc-900 dark:bg-opacity-80 z-10">
          <Spinner size="xl" />
        </div>
      )}

      {error && (
        <div
          role="alert"
          className="absolute inset-0 flex items-center justify-center text-red-600 dark:text-red-400 bg-white bg-opacity-80 dark:bg-zinc-900 dark:bg-opacity-80 z-10"
        >
          {error}
        </div>
      )}

      <svg
        ref={svgRef}
        className="w-full h-full"
        role="tree"
        aria-label={t('edu.skillTree.svgAriaLabel')}
      />

      {selectedSkill && (
        <aside
          role="dialog"
          aria-modal="true"
          aria-labelledby="skill-dialog-title"
          tabIndex={-1}
          className="fixed top-1/2 left-1/2 max-w-md w-full bg-white dark:bg-zinc-800 p-6 rounded shadow-lg z-20 transform -translate-x-1/2 -translate-y-1/2"
        >
          <h3 id="skill-dialog-title" className="text-xl font-semibold mb-2 text-gray-900 dark:text-gray-100">
            {selectedSkill.name}
          </h3>
          <p className="mb-4 text-gray-700 dark:text-gray-300">{selectedSkill.description || t('edu.skillTree.noDescription')}</p>

          <label htmlFor="progressRange" className="block mb-1 font-medium text-gray-900 dark:text-gray-100">
            {t('edu.skillTree.progressLabel')} ({selectedSkill.progress}%)
          </label>
          <input
            id="progressRange"
            type="range"
            min={0}
            max={100}
            value={selectedSkill.progress}
            onChange={(e) => handleProgressChange(selectedSkill.id, Number(e.target.value))}
            className="w-full"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={selectedSkill.progress}
          />

          <div className="mt-6 flex justify-end">
            <button
              onClick={() => setSelectedSkill(null)}
              className="px-4 py-2 bg-indigo-600 text-white rounded hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              {t('common.close')}
            </button>
          </div>
        </aside>
      )}

      {selectedSkill && (
        <div
          className="fixed inset-0 bg-black bg-opacity-40 z-10"
          onClick={() => setSelectedSkill(null)}
          aria-hidden="true"
        />
      )}
    </section>
  );
};

export default React.memo(SkillTreeMap);
