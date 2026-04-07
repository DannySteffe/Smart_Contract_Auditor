import { detectLanguage } from '@/lib/language-detector';

const GITHUB_API_BASE_URL = 'https://api.github.com';
const MAX_FILES_TO_ANALYZE = 10;
const MAX_FILE_SIZE_BYTES = 200_000;
const MAX_TOTAL_SIZE_BYTES = 250_000;

const SMART_CONTRACT_EXTENSIONS = new Set(['.sol', '.vy', '.cairo']);

type SupportedExtension = '.sol' | '.vy' | '.cairo';

interface GitHubTreeNode {
  path: string;
  type: 'blob' | 'tree';
  sha: string;
  size?: number;
}

interface GitHubRepositoryData {
  default_branch: string;
}

interface GitHubTreeData {
  tree: GitHubTreeNode[];
  truncated: boolean;
}

interface GitHubBlobData {
  content?: string;
  encoding?: string;
}

export interface RepoContractFile {
  path: string;
  content: string;
  extension: SupportedExtension;
  size: number;
}

export interface RepoFetchResult {
  owner: string;
  repo: string;
  branch: string;
  dominantExtension: SupportedExtension;
  contractCode: string;
  fileName: string;
  files: Array<{ path: string; size: number }>;
  language: string;
}

interface ParsedGitHubUrl {
  owner: string;
  repo: string;
  mode: 'repo' | 'blob' | 'tree';
  ref?: string;
  scopedPath?: string;
}

export function parseGitHubRepositoryUrl(url: string): ParsedGitHubUrl {
  let parsedUrl: URL;

  try {
    parsedUrl = new URL(url.trim());
  } catch {
    throw new Error('Invalid GitHub repository URL');
  }

  if (parsedUrl.hostname !== 'github.com' && parsedUrl.hostname !== 'www.github.com') {
    throw new Error('Only github.com repository links are supported');
  }

  const parts = parsedUrl.pathname.split('/').filter(Boolean);
  if (parts.length < 2) {
    throw new Error('GitHub URL must include owner and repository name');
  }

  const owner = parts[0];
  const repo = parts[1].replace(/\.git$/i, '');

  if (!owner || !repo) {
    throw new Error('Could not parse repository owner/name from URL');
  }

  // Supports:
  // - https://github.com/owner/repo
  // - https://github.com/owner/repo/tree/<branch>/<folder>
  // - https://github.com/owner/repo/blob/<branch>/<file>
  if (parts[2] === 'blob') {
    if (parts.length < 5) {
      throw new Error('Invalid GitHub file URL');
    }

    return {
      owner,
      repo,
      mode: 'blob',
      ref: parts[3],
      scopedPath: parts.slice(4).join('/')
    };
  }

  if (parts[2] === 'tree') {
    if (parts.length < 4) {
      throw new Error('Invalid GitHub folder URL');
    }

    return {
      owner,
      repo,
      mode: 'tree',
      ref: parts[3],
      scopedPath: parts.slice(4).join('/') || undefined
    };
  }

  return { owner, repo, mode: 'repo' };
}

export async function fetchContractsFromGitHubRepository(url: string): Promise<RepoFetchResult> {
  const parsed = parseGitHubRepositoryUrl(url);
  const { owner, repo } = parsed;

  const repository = await githubFetch<GitHubRepositoryData>(`/repos/${owner}/${repo}`);
  const branch = parsed.ref || repository.default_branch;

  const treeData = await githubFetch<GitHubTreeData>(`/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`);

  if (treeData.truncated) {
    throw new Error('Repository is too large to analyze via GitHub API tree listing');
  }

  const contractNodes = treeData.tree
    .filter((node) => node.type === 'blob')
    .filter((node) => getExtension(node.path) !== null)
    .filter((node) => (node.size || 0) <= MAX_FILE_SIZE_BYTES)
    .sort((a, b) => (b.size || 0) - (a.size || 0));

  const scopedNodes = filterByScope(contractNodes, parsed);

  if (scopedNodes.length === 0) {
    if (parsed.mode === 'blob') {
      throw new Error('No supported smart contract file found at the provided GitHub file URL');
    }
    if (parsed.mode === 'tree') {
      throw new Error('No Solidity, Vyper, or Cairo files found in the provided GitHub folder path');
    }

    throw new Error('No Solidity, Vyper, or Cairo files found in repository');
  }

  const selectedNodes = parsed.mode === 'blob'
    ? scopedNodes.slice(0, 1)
    : scopedNodes.slice(0, MAX_FILES_TO_ANALYZE);

  const fetchedFiles: RepoContractFile[] = [];
  let totalSize = 0;

  for (const node of selectedNodes) {
    if ((node.size || 0) + totalSize > MAX_TOTAL_SIZE_BYTES) {
      continue;
    }

    const blob = await githubFetch<GitHubBlobData>(`/repos/${owner}/${repo}/git/blobs/${node.sha}`);
    if (!blob.content || blob.encoding !== 'base64') {
      continue;
    }

    const extension = getExtension(node.path);
    if (!extension) {
      continue;
    }

    const decoded = Buffer.from(blob.content.replace(/\n/g, ''), 'base64').toString('utf-8');
    if (!decoded.trim()) {
      continue;
    }

    totalSize += node.size || decoded.length;
    fetchedFiles.push({
      path: node.path,
      content: decoded,
      extension,
      size: node.size || decoded.length
    });
  }

  if (fetchedFiles.length === 0) {
    throw new Error('Contract files were found, but could not be fetched from GitHub API');
  }

  const dominantExtension = pickDominantExtension(fetchedFiles);
  const dominantFiles = fetchedFiles
    .filter((file) => file.extension === dominantExtension)
    .sort((a, b) => b.size - a.size);

  const mainFile = dominantFiles[0];
  const bundledCode = dominantFiles.length === 1
    ? dominantFiles[0].content.trim()
    : dominantFiles
      .map((file) => `// FILE: ${file.path}\n${file.content.trim()}`)
      .join('\n\n');

  const language = detectLanguage(bundledCode, mainFile.path).language;

  return {
    owner,
    repo,
    branch,
    dominantExtension,
    contractCode: bundledCode,
    fileName: mainFile.path.split('/').pop() || `contract${dominantExtension}`,
    files: dominantFiles.map((file) => ({ path: file.path, size: file.size })),
    language
  };
}

function filterByScope(nodes: GitHubTreeNode[], parsed: ParsedGitHubUrl): GitHubTreeNode[] {
  if (parsed.mode === 'repo') {
    return nodes;
  }

  if (!parsed.scopedPath) {
    return nodes;
  }

  if (parsed.mode === 'blob') {
    return nodes.filter((node) => node.path === parsed.scopedPath);
  }

  const prefix = parsed.scopedPath.endsWith('/') ? parsed.scopedPath : `${parsed.scopedPath}/`;
  return nodes.filter((node) => node.path.startsWith(prefix));
}

function pickDominantExtension(files: RepoContractFile[]): SupportedExtension {
  const scores: Record<SupportedExtension, number> = {
    '.sol': 0,
    '.vy': 0,
    '.cairo': 0
  };

  for (const file of files) {
    scores[file.extension] += 1;
  }

  const sorted = Object.entries(scores).sort((a, b) => b[1] - a[1]);
  return sorted[0][0] as SupportedExtension;
}

function getExtension(path: string): SupportedExtension | null {
  const lowerPath = path.toLowerCase();
  if (lowerPath.endsWith('.sol')) return '.sol';
  if (lowerPath.endsWith('.vy')) return '.vy';
  if (lowerPath.endsWith('.cairo')) return '.cairo';

  const ext = lowerPath.slice(lowerPath.lastIndexOf('.'));
  if (SMART_CONTRACT_EXTENSIONS.has(ext)) {
    return ext as SupportedExtension;
  }

  return null;
}

async function githubFetch<T>(path: string): Promise<T> {
  const token = process.env.GITHUB_TOKEN || process.env.GH_TOKEN;

  const callGitHub = async (useAuth: boolean) => {
    return fetch(`${GITHUB_API_BASE_URL}${path}`, {
      headers: {
        Accept: 'application/vnd.github+json',
        'User-Agent': 'Smart-Contract-Auditor',
        ...(useAuth && token ? { Authorization: `Bearer ${token}` } : {})
      },
      cache: 'no-store'
    });
  };

  let response = await callGitHub(Boolean(token));

  // If token is invalid, retry once without auth so public repositories still work.
  if (response.status === 401 && token) {
    response = await callGitHub(false);
  }

  if (!response.ok) {
    if (response.status === 401) {
      throw new Error('GitHub token is invalid. Regenerate GITHUB_TOKEN or remove it for public repositories');
    }
    if (response.status === 404) {
      throw new Error('Repository not found or is private');
    }
    if (response.status === 403) {
      throw new Error('GitHub API rate limit exceeded. Add GITHUB_TOKEN to environment');
    }

    const errorBody = await response.text().catch(() => '');
    throw new Error(`GitHub API request failed (${response.status}): ${errorBody || 'Unknown error'}`);
  }

  return response.json() as Promise<T>;
}
