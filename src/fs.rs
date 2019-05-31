use indicatif::{ProgressBar, ProgressStyle};
use num_cpus;
use rayon;
use sha2::{Sha512Trunc256, Digest};
use std::collections::{BinaryHeap, BTreeSet};
use std::cmp::Ordering;
use std::fs::File;
use std::io::{BufReader, BufRead};
use std::path::PathBuf;
use std::sync::mpsc::{self, Sender, SyncSender, Receiver};

#[derive(Clone)]
pub struct Hash {
    pub path: PathBuf,
    pub hash: [u8; 32]
}

impl Hash {
    pub fn new(p: &PathBuf, h: &[u8]) -> Self {
        let mut hash = Hash { path: p.to_path_buf(), hash: [0u8; 32] };
        hash.hash.copy_from_slice(h);
        hash
    }
}

#[derive(Clone)]
enum JobType {
    Digest(u64, PathBuf),
    Scan(u64, PathBuf),
    Hash(u64, Hash),
    Done(u64)
}

pub fn hash(paths: Vec<PathBuf>) -> Vec<Hash> {

    fn classify_paths(paths: Vec<PathBuf>) -> Vec<JobType> {
        let mut jobs = Vec::new();
        for p in paths {
            if let Ok(meta) = p.symlink_metadata() {
                if meta.is_file() {
                    jobs.push(JobType::Digest(0, p.to_path_buf()));
                } else if meta.is_dir() {
                    jobs.push(JobType::Scan(0, p.to_path_buf()));
                }
            }
        }
        jobs
    }

    fn worker(rx: Receiver<JobType>, tx: Sender<JobType>) {
        'worker: loop {
            if let Ok(job) = rx.recv() {
                match job {
                    JobType::Digest(job_no, path) => {
                        // digest the file
                        if let Ok(file) = File::open(&path) {
                            let mut hasher = Sha512Trunc256::new();
                            let mut reader = BufReader::with_capacity(8192, file);
                            'digest: loop {
                                let len = {
                                    let buf = reader.fill_buf().unwrap();
                                    hasher.input(buf);
                                    buf.len()
                                };
                                if len == 0 {
                                    break 'digest;
                                }
                                reader.consume(len);
                            }
                            tx.send(JobType::Hash(job_no, Hash::new(&path, hasher.result().as_slice()))).unwrap();
                        } else {
                            tx.send(JobType::Done(job_no)).unwrap();
                        }
                    },
                    JobType::Scan(job_no, dir) => {
                        let dir_iter = dir.read_dir().expect(&format!("read_dir failed: {:?}", dir));
                        let paths: Vec<PathBuf> = dir_iter.map(|res| res.unwrap().path()).collect();
                        let jobs = classify_paths(paths);
                        for j in jobs {
                            tx.send(j).unwrap();
                        }
                        tx.send(JobType::Done(job_no)).unwrap();
                    },
                    JobType::Hash(_, _) |
                    JobType::Done(_) => {}
                }
            } else {
                break 'worker;
            }
        }
    }

    fn coordinator(paths: Vec<PathBuf>, hashes: &mut Vec<Hash>) {

        // initialize the progress bar
        let mut total: u64 = 0;
        let mut job_no: u64 = 1;
        let pb = ProgressBar::new(total);
        pb.set_style(ProgressStyle::default_bar()
            .template("[ETA: {eta_precise}] [{bar}] {pos:>}/{len:} {wide_msg}")
            .progress_chars("=>-"));

        // convert the initial set of paths into jobs
        let mut jobs = BinaryHeap::from(classify_paths(paths));
        let mut waiting = BTreeSet::new();

        // set up the feedback channel
        let (tx, rx): (Sender<JobType>, Receiver<JobType>) = mpsc::channel();

        // spin up the workers
        let mut workers = Vec::new();
        for _ in 0..num_cpus::get() {
            let (thread_tx, thread_rx): (SyncSender<JobType>, Receiver<JobType>) = mpsc::sync_channel(2);
            workers.push(thread_tx);
            let coord_tx = tx.clone();
            rayon::spawn(|| worker(thread_rx, coord_tx));
        }

        // loop until all jobs are processed
        'processing: loop {

            // try to farm out jobs to workers
            'sending: for worker in &workers {
                if let Some(job) = jobs.peek() {
                    let job = JobType::new_from(job_no, job);
                    if let Ok(_) = worker.try_send(job) {
                        // add the job number to the list of waiting jobs
                        waiting.insert(job_no);

                        // increment the job number and total
                        job_no += 1;

                        // remove the job from the queue
                        jobs.pop();
                    }
                } else {
                    break 'sending;
                }
            }

            // check for incoming jobs and sort it
            if let Ok(job) = rx.try_recv() {
                waiting.remove(&job.job_no());
                match job {
                    JobType::Digest(_, _) => {
                        total += 1;
                        pb.set_length(total);
                        jobs.push(job);
                    }
                    JobType::Scan(_, ref dir) => {
                        pb.set_message(&format!("Scan: {}", dir.to_str().unwrap()));
                        jobs.push(job);
                    },
                    JobType::Hash(_, hash) => {
                        pb.inc(1);
                        pb.set_message(&format!("Hash: {}", hash.path.to_str().unwrap()));
                        hashes.push(hash);
                    }
                    JobType::Done(_) => {
                    }
                }
            }

            // check to see if all of our jobs are done
            if waiting.is_empty() {
                break 'processing;
            }
        }

        pb.set_message("Done...");
        pb.finish();
    }
    
    let mut hashes = Vec::new();
    let pool = rayon::ThreadPoolBuilder::new().num_threads(num_cpus::get() + 1).build().unwrap();
    pool.install(|| coordinator(paths, &mut hashes));
    hashes
}

impl Ord for JobType {
    fn cmp(&self, other: &JobType) -> Ordering {
        match self {
            JobType::Digest(_, _) => {
                match other {
                    JobType::Digest(_, _) => {
                        Ordering::Equal
                    },
                    JobType::Scan(_, _) => {
                        Ordering::Less
                    },
                    JobType::Hash(_, _) => {
                        Ordering::Greater
                    },
                    JobType::Done(_) => {
                        Ordering::Greater
                    }
                }
            },
            JobType::Scan(_, _) => {
                match other {
                    JobType::Digest(_, _) => {
                        Ordering::Greater
                    },
                    JobType::Scan(_, _) => {
                        Ordering::Equal
                    },
                    JobType::Hash(_, _) => {
                        Ordering::Greater
                    },
                    JobType::Done(_) => {
                        Ordering::Greater
                    }
                }
            },
            JobType::Hash(_, _) => {
                match other {
                    JobType::Digest(_, _) => {
                        Ordering::Less
                    },
                    JobType::Scan(_, _) => {
                        Ordering::Less
                    },
                    JobType::Hash(_, _) => {
                        Ordering::Equal
                    },
                    JobType::Done(_) => {
                        Ordering::Greater
                    }
                }
            },
            JobType::Done(_) => {
                match other {
                    JobType::Digest(_, _) => {
                        Ordering::Less
                    },
                    JobType::Scan(_, _) => {
                        Ordering::Less
                    },
                    JobType::Hash(_, _) => {
                        Ordering::Less
                    },
                    JobType::Done(_) => {
                        Ordering::Equal
                    }
                }
            }
        }
    }
}

impl PartialOrd for JobType {
    fn partial_cmp(&self, other: &JobType) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Eq for JobType {}

impl PartialEq for JobType {
    fn eq(&self, other: &JobType) -> bool {
        match self {
            JobType::Digest(_, _) => {
                match other {
                    JobType::Digest(_, _) => true,
                    JobType::Scan(_, _) |
                    JobType::Hash(_, _) |
                    JobType::Done(_) => false
                }
            },
            JobType::Scan(_, _) => {
                match other {
                    JobType::Scan(_, _) => true,
                    JobType::Digest(_, _) |
                    JobType::Hash(_, _) |
                    JobType::Done(_) => false
                }
            },
            JobType::Hash(_, _) => {
                match other {
                    JobType::Hash(_, _) => true,
                    JobType::Digest(_, _) |
                    JobType::Scan(_, _) |
                    JobType::Done(_) => false
                }
            },
            JobType::Done(_) => {
                match other {
                    JobType::Done(_) => true,
                    JobType::Digest(_, _) |
                    JobType::Scan(_, _) |
                    JobType::Hash(_, _) => false
                }
            }
        }
    }
}

impl JobType {
    fn new_from(job_no: u64, job: &JobType) -> Self {
        match job {
            JobType::Digest(_, file) => {
                JobType::Digest(job_no, file.to_path_buf())
            },
            JobType::Scan(_, dir) => {
                JobType::Scan(job_no, dir.to_path_buf())
            },
            JobType::Hash(_, hash) => {
                JobType::Hash(job_no, hash.clone())
            },
            JobType::Done(_) => {
                JobType::Done(job_no)
            }
        }
    }

    fn job_no(&self) -> u64 {
        match *self {
            JobType::Digest(job_no, _) |
            JobType::Scan(job_no, _) |
            JobType::Hash(job_no, _) |
            JobType::Done(job_no) => job_no
        }
    }
}
