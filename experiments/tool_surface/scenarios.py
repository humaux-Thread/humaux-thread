"""Pilot scenario suite for X2/X4: user messages an agent receives, labelled with the acceptable FIRST Humaux action.

Responsibility: synthetic, tool-name-free situations covering every job family, the confusion pairs GPT batch 22
listed (remember vs revise, brief vs project.get, task.finish vs checkpoint yield, archive vs forget, share vs public
contribution, people.profile vs recall.search, plan.reschedule vs memory correction, files.search vs recall,
code.search vs recall), and no-call cases. EN and ZH. No real data.
Depends on: catalog action ids. Used by: run.py.
Fields: expect = acceptable first action ids ([] = the agent must not call Humaux); args = {field: regex} checked on
the first call when it matched (case-insensitive).
"""

C = []


def case(id, family, lang, prompt, expect, args=None):
    C.append({"id": id, "family": family, "lang": lang, "prompt": prompt, "expect": expect, "args": args or {}})


# orient
case("br1", "brief", "en", "New session. Continue the importer project where we left off.", ["brief.get"])
case("br2", "brief", "zh", "我们接着昨天另一个 agent 没做完的活继续。", ["brief.get"])
case("br3", "brief", "en", "Your context was just compacted. Pick up the current task again.", ["brief.get"])
case("br4", "brief", "zh", "开始工作前先看看这个项目现在是什么状况、有哪些约束。", ["brief.get", "project.get"])
# recall
case("rc1", "recall", "en", "Have we ever hit 'deadlock detected' on the orders table before? What did we do?",
     ["recall.search", "recall.cases"], {"query": "deadlock"})
case("rc2", "recall", "zh", "我之前跟你说过我更喜欢哪种测试框架？", ["recall.search"])
case("rc3", "recall", "en", "List every decision we recorded about the billing module since September.",
     ["recall.list"])
case("rc4", "recall", "en", "The search hit m_1001 was cut off. Show me the full text.", ["recall.get"],
     {"memory_ref": "m_1001"})
case("rc5", "recall", "zh", "这条记忆 m_1001 以前是怎么写的？被谁替换了？", ["recall.history"], {"memory_ref": "m_1001"})
case("rc6", "recall", "en", "Before you pick a queue library, check whether we rejected one before.",
     ["recall.search"])
# remember
case("rm1", "remember", "en", "We decided: use Postgres advisory locks instead of Redis for the scheduler, because "
     "we run a single node. Keep that.", ["remember.put"], {"memory_type": "decision"})
case("rm2", "remember", "zh", "这个 bug 的根因是时区没转 UTC，修法是在入库前统一转换。记下来。", ["remember.put"],
     {"memory_type": "fix"})
case("rm3", "remember", "en", "From now on, answer me in Chinese and keep replies short.", ["remember.put",
     "revise.pin"], {})
case("rm4", "remember", "zh", "客户王总今天在微信里说价格太高，我们给了 9 折，他说下周再看。帮我记一下这次沟通。",
     ["remember.put", "people.resolve"])
case("rm5", "remember", "en", "We tried caching embeddings in Redis and dropped it — memory usage was too high. "
     "Note that we rejected it.", ["remember.put"], {"memory_type": "rejection"})
# revise
case("rv1", "revise", "en", "Memory m_1001 says the API rate limit is 100/s. It's actually 60/s. Fix it.",
     ["revise.correct"], {"memory_ref": "m_1001"})
case("rv2", "revise", "zh", "m_1001 这条已经过时了，新的结论在 m_1002，标记一下替换关系。", ["revise.supersede"])
case("rv3", "revise", "en", "Always remember the rule in m_1001; it must show up in every session.", ["revise.pin"])
case("rv4", "revise", "en", "m_1001 is obsolete but keep it for the record; just hide it from search.",
     ["revise.archive"])
# share / forget / confusions
case("sh1", "share", "en", "Make memory m_1001 visible in my 'fragrance' workspace too.", ["share.preview"])
case("fg1", "forget", "zh", "把 m_1001 这条彻底删掉，我不想再看到它。", ["forget.preview"])
case("fg2", "forget", "en", "Delete everything you know about my ex, Liang. All of it.", ["forget.preview",
     "people.resolve"])
case("cf1", "confusion", "en", "m_1001 is outdated — archive it, don't delete it.", ["revise.archive"])
case("cf2", "confusion", "en", "Share this debugging lesson with everyone who uses Humaux, anonymised.",
     ["public_contribute.preview"])
# project / lock / canvas
case("pj1", "project", "en", "The project goal changed: we now target self-hosted users first. Update the goal.",
     ["project.publish"], {"facet": "goal"})
case("pj2", "project", "zh", "我要改共享的 config.toml，别的 agent 也可能在改，先锁住。", ["project.lock_acquire"])
case("pj3", "project", "en", "Show me the team's task board.", ["project.canvas_get"])
# checkpoint / task
case("ck1", "checkpoint", "en", "Step 2 of 5 is done (schema migrated). Save progress before you run the long "
     "backfill.", ["checkpoint.save"], {"disposition": "continue"})
case("ck2", "checkpoint", "zh", "我的额度快用完了，你先停下，把进度交给下一个 agent。", ["checkpoint.save"],
     {"disposition": "yield"})
case("tk1", "task", "en", "Create a task to add rate limiting to the export endpoint.", ["task.create"])
case("tk2", "task", "en", "Take task t_501 — make sure no other agent works on it at the same time.",
     ["task.claim"], {"task_ref": "t_501"})
case("tk3", "task", "zh", "t_501 已经完成并且测试通过了，结案。", ["task.finish"], {"outcome": "done"})
case("tk4", "task", "en", "I can't continue t_501 until the user sends the API key. Mark it.", ["task.block"])
case("tk5", "confusion", "en", "Session is ending but t_501 is only half done. Wrap up so someone else can continue.",
     ["checkpoint.save"], {"disposition": "yield"})
# people
case("pp1", "people", "en", "Before my call with Acme's buyer Maria tomorrow, what do we know about her?",
     ["people.profile", "people.resolve"])
case("pp2", "people", "zh", "新客户：深圳某某电子的采购李经理，以后会常联系，帮我建个档。", ["people.register"],
     {"kind": "customer|person"})
case("pp3", "people", "en", "Maria's email is maria@acme.example — add it to her record.", ["people.link_key",
     "people.resolve"])
case("pp4", "people", "zh", "她今天回消息很冷淡，我觉得是上次迟到的事还在生气。记下这个判断和依据。",
     ["people.record_affect", "remember.put", "people.resolve"])
case("cf3", "confusion", "en", "What do we know about the 'Osmene' brand positioning?", ["recall.search"])
# plan
case("pl1", "plan", "en", "Remind me to follow up with Maria next Tuesday about the sample order.", ["plan.add"],
     {"kind": "follow_up|reminder"})
case("pl2", "plan", "zh", "这周有哪些到期要跟进的事？", ["plan.due"])
case("pl3", "plan", "en", "Push the Maria follow-up to Friday.", ["plan.reschedule", "plan.list"])
case("cf4", "confusion", "zh", "提醒 pl_77 的时间设错了，改到下周一。", ["plan.reschedule"], {"plan_ref": "pl_77"})
# files
case("fl1", "files", "en", "Here's a screenshot of the customer's WhatsApp chat (chat.png). Keep it as evidence.",
     ["files.attach"])
case("fl2", "files", "zh", "把之前存的那张报价单截图 a_88 里的文字识别出来。", ["files.extract"],
     {"artifact_ref": "a_88"})
case("cf5", "confusion", "en", "Find the PDF contract we stored for Acme last month.", ["files.search"])
# code
case("cd1", "code", "en", "Where is the retry logic for webhook delivery implemented?", ["code.search"])
case("cd2", "code", "en", "If I change the signature of parse_invoice, what breaks?", ["code.impact"],
     {"symbol": "parse_invoice"})
case("cf6", "confusion", "zh", "我们代码里 OrderService 是在哪定义的？", ["code.symbol", "code.search"])
# review / status
case("rw1", "review", "en", "Is there anything waiting for my approval in the memory system?", ["review.pending"])
case("rw2", "review", "zh", "那条自动提炼出来的规则 pr_9 我同意，采纳。", ["review.accept"], {"proposal_ref": "pr_9"})
case("st1", "status", "en", "How much of my monthly quota have I used?", ["status.account"])
case("st2", "status", "zh", "我昨天上传的东西都处理完了吗？", ["status.health", "files.status"])
# public
case("pb1", "public", "en", "Has anyone in the community documented a fix for Qdrant snapshot restore failures?",
     ["public_read.search", "recall.search"])
# no-call
case("nc1", "nocall", "en", "What's 17 times 23?", [])
case("nc2", "nocall", "zh", "帮我把这句话翻译成英文：今天天气很好。", [])
case("nc3", "nocall", "en", "Explain what a mutex is in two sentences.", [])
case("nc4", "nocall", "en", "Thanks, that's all for now!", [])
case("nc5", "nocall", "zh", "你好", [])

CASES = C
assert len({c["id"] for c in C}) == len(C)
