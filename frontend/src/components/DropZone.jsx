import { useState, useRef } from 'react';
import { Upload, FileText } from 'lucide-react';

export default function DropZone({ onFile }) {
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef(null);

  const handle = (file) => {
    if (file && (file.name.endsWith('.binetflow') || file.name.endsWith('.csv'))) {
      onFile(file);
    }
  };

  return (
    <div
      onDragEnter={(e) => { e.preventDefault(); setDragging(true); }}
      onDragLeave={(e) => { e.preventDefault(); setDragging(false); }}
      onDragOver={(e) => e.preventDefault()}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        handle(e.dataTransfer.files[0]);
      }}
      onClick={() => inputRef.current?.click()}
      className={`w-full max-w-lg mx-auto rounded-2xl border-2 border-dashed cursor-pointer
                  flex flex-col items-center justify-center gap-4 p-16 transition-colors
                  ${dragging
                    ? 'border-red-400 bg-red-50'
                    : 'border-slate-200 bg-white hover:border-slate-300 hover:bg-slate-50'
                  }`}
    >
      <div className={`p-4 rounded-full ${dragging ? 'bg-red-100' : 'bg-slate-100'}`}>
        {dragging
          ? <FileText size={28} className="text-red-500" />
          : <Upload size={28} className="text-slate-400" />
        }
      </div>

      <div className="text-center">
        <p className="font-semibold text-slate-900 text-base">
          {dragging ? 'Release to load' : 'Drop your CTU-13 .binetflow file here to begin'}
        </p>
        <p className="text-sm text-slate-500 mt-1">
          or <span className="text-red-500 underline">browse</span> to select a file
        </p>
        <p className="text-xs text-slate-400 mt-3">
          Supports .binetflow and .csv · First 50,000 rows sampled for fast analysis
        </p>
      </div>

      <input
        ref={inputRef}
        type="file"
        accept=".binetflow,.csv"
        className="hidden"
        onChange={(e) => handle(e.target.files[0])}
      />
    </div>
  );
}
