import Editor, { type OnMount } from "@monaco-editor/react";
import type { editor as MonacoEditor } from "monaco-editor";
import { useCallback, useEffect, useRef } from "react";
import type { FindingLocation, SourceFile } from "../types/domain";

type MonacoApi = typeof import("monaco-editor");

export function MonacoSource({ source, location, readOnly = true, height = "100%", theme = "vs-dark" }: { source?: SourceFile; location: FindingLocation; readOnly?: boolean; height?: string; theme?: "vs" | "vs-dark" }) {
  const editorRef = useRef<MonacoEditor.IStandaloneCodeEditor | null>(null);
  const monacoRef = useRef<MonacoApi | null>(null);
  const decorations = useRef<MonacoEditor.IEditorDecorationsCollection | undefined>(undefined);
  const applyLocation = useCallback(() => {
    const editor = editorRef.current;
    const monaco = monacoRef.current;
    if (!editor || !monaco) return;
    decorations.current ??= editor.createDecorationsCollection();
    const startLine = Math.max(1, location.region.startLine || 1);
    const startColumn = Math.max(1, location.region.startColumn || 1);
    const endLine = Math.max(startLine, location.region.endLine || startLine);
    const endColumn = Math.max(1, location.region.endColumn || startColumn + 1);
    decorations.current.set([{ range: new monaco.Range(startLine, startColumn, endLine, endColumn), options: { className: "monaco-finding-line", inlineClassName: "monaco-finding-inline", glyphMarginClassName: "monaco-finding-glyph", overviewRuler: { color: "#f97316", position: monaco.editor.OverviewRulerLane.Right } } }]);
    editor.revealLineInCenter(startLine);
    editor.setPosition({ lineNumber: startLine, column: startColumn });
  }, [location]);
  useEffect(() => { applyLocation(); }, [applyLocation, source?.absolutePath]);
  const onMount: OnMount = (editor, monaco) => { editorRef.current = editor; monacoRef.current = monaco; applyLocation(); };
  if (!source) return <div className="editor-placeholder">Select a finding to load source.</div>;
  return <Editor height={height} path={source.absolutePath} language={source.language} value={source.content} theme={theme} onMount={onMount} options={{ readOnly, domReadOnly: readOnly, minimap: { enabled: false }, fontFamily: "'JetBrains Mono', 'Cascadia Code', Consolas, monospace", fontSize: 13, lineHeight: 21, scrollBeyondLastLine: false, renderLineHighlight: "all", glyphMargin: true, folding: true, automaticLayout: true, padding: { top: 12 }, stickyScroll: { enabled: false } }} />;
}
