# ci/ai-review/pr_review_bot_v2.py

import asyncio
import logging
import os
from typing import Optional
from github import Github, PullRequest
from github.PullRequest import PullRequest as PR
from ai_core.language_model import AIReviewModel

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')


class PRReviewBot:
    """
    Бот для автоматического AI-код-ревью Pull Request'ов.
    """

    def __init__(self, github_token: str, repo_name: str):
        self.github = Github(github_token)
        self.repo = self.github.get_repo(repo_name)
        self.ai_model = AIReviewModel()

    async def review_pull_request(self, pr_number: int) -> None:
        pr: PR = self.repo.get_pull(pr_number)
        logger.info(f"🔍 Начало AI-код-ревью PR #{pr_number}: {pr.title}")

        changed_files = list(pr.get_files())
        if not changed_files:
            logger.info("Нет изменённых файлов в PR.")
            return

        review_comments = []
        security_warnings = []
        style_suggestions = []

        for file in changed_files:
            filename = file.filename
            patch = getattr(file, 'patch', '')
            content = self._get_file_content(pr, filename)

            if not content or not patch:
                continue

            review_result = await self.ai_model.review_code(
                code=content,
                filename=filename,
                diff=patch
            )

            if review_result:
                if review_result.get("review"):
                    review_comments.append((filename, review_result["review"]))
                if review_result.get("security"):
                    security_warnings.append((filename, review_result["security"]))
                if review_result.get("style"):
                    style_suggestions.append((filename, review_result["style"]))

        if review_comments or security_warnings or style_suggestions:
            comment_body = self._format_review_comments(
                review_comments, security_warnings, style_suggestions
            )
            pr.create_issue_comment(comment_body)
            logger.info(f"AI-ревью добавлено к PR #{pr_number}")
        else:
            logger.info(f"AI не обнаружил замечаний в PR #{pr_number}")

    def _get_file_content(self, pr: PR, filename: str) -> str:
        try:
            file_content = self.repo.get_contents(filename, ref=pr.head.sha)
            return file_content.decoded_content.decode("utf-8")
        except Exception as e:
            logger.error(f"Ошибка чтения файла {filename} в PR #{pr.number}: {e}")
            return ""

    def _format_review_comments(
        self,
        general: list[tuple[str, str]],
        security: list[tuple[str, str]],
        style: list[tuple[str, str]],
    ) -> str:
        parts = ["### 🤖 AI Review Summary\n"]

        if general:
            parts.append("#### 📄 Общие замечания:\n")
            for fname, comment in general:
                parts.append(f"**{fname}**:\n{comment}\n")

        if security:
            parts.append("\n#### 🔐 Замечания по безопасности:\n")
            for fname, warning in security:
                parts.append(f"**{fname}**:\n{warning}\n")

        if style:
            parts.append("\n#### 🎨 Замечания по стилю:\n")
            for fname, suggestion in style:
                parts.append(f"**{fname}**:\n{suggestion}\n")

        return "\n".join(parts)


async def main():
    github_token = os.getenv("GITHUB_TOKEN")
    repo_name = os.getenv("REPO_NAME")
    pr_number_str = os.getenv("PR_NUMBER")

    if not github_token or not repo_name or not pr_number_str or not pr_number_str.isdigit():
        logger.error("Ошибка: нужны переменные окружения GITHUB_TOKEN, REPO_NAME и PR_NUMBER")
        return

    pr_number = int(pr_number_str)
    bot = PRReviewBot(github_token, repo_name)
    await bot.review_pull_request(pr_number)


if __name__ == "__main__":
    asyncio.run(main())
