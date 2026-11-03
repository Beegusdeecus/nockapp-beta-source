export interface PostReference { postId: string; url: string }
export interface ExternalReference { url: string; postId?: string }
export type CredentialClaim = { kind: 'x-account' | 'followers-1k' | 'followers-10k' | 'followed-by'; account?: string };
export type PassportFact = 'account-controlled' | 'followers-over-10000';
export interface PostFactReference { profile: 'nockapp-x-post-fact-v1'; fact: PassportFact; challenge: string }
export type ZkidFact = 'account-controlled' | 'followers-at-least-10000';
export interface ZkidReference { profile: 'nockapp-zkid-post-reference-v1'; nonce: string; facts: ZkidFact[] }
export interface Author { credentials: CredentialClaim[]; passport?: PostFactReference[]; zkid?: ZkidReference }
export interface PostIdentity { id: string; createdAt: number }
export interface Thread {
  id: string; postNumber: string; title: string; body: string; author: Author; createdAt: number; references: ExternalReference[];
}
export interface Comment {
  id: string; postNumber: string; threadId: string; body: string; author: Author; createdAt: number; references: ExternalReference[];
}
export interface ForumData { schema: 2; nextPostNumber: number; threads: Thread[]; comments: Comment[] }
export interface ReferenceResults { threads: Thread[]; comments: { comment: Comment; thread: Thread }[] }
export type View =
  | { kind: 'home' }
  | { kind: 'results'; post: PostReference }
  | { kind: 'thread'; post: PostReference; threadId: string; focusPostId?: string }
  | { kind: 'create'; post: PostReference };
export interface Navigation { stack: View[]; updatedAt: number; scroll: Record<string, number> }
export type Selection = { at: number; nonce: string } & ({ kind: 'post'; post: PostReference } | { kind: 'help' });
