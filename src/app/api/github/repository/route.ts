import { NextRequest, NextResponse } from 'next/server';
import { fetchContractsFromGitHubRepository } from '@/lib/github-repository';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const githubUrl = body?.githubUrl;

    if (!githubUrl || typeof githubUrl !== 'string') {
      return NextResponse.json(
        { error: 'GitHub repository URL is required' },
        { status: 400 }
      );
    }

    const result = await fetchContractsFromGitHubRepository(githubUrl);

    return NextResponse.json({
      repository: {
        owner: result.owner,
        name: result.repo,
        branch: result.branch
      },
      language: result.language,
      fileName: result.fileName,
      filesIncluded: result.files,
      contractCode: result.contractCode
    });
  } catch (error) {
    console.error('GitHub repository fetch error:', error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to fetch repository content' },
      { status: 500 }
    );
  }
}
