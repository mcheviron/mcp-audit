package scanner

type bodyAssessment struct {
	text              string
	score             float64
	entropy           float64
	band              string
	class             ResponseClass
	containsMetadata  bool
	containsAwsKey    bool
	containsGcpToken  bool
	containsInternal  bool
	promptInjectMatch string
	promptInjectConf  float64
}

func (a bodyAssessment) containsPromptInject() bool {
	return a.promptInjectConf >= minConfidenceForHIGH
}

func assessBody(body, contentType string) bodyAssessment {
	return assessBodyWithContext(body, contentType, "", "")
}

func assessBodyWithContext(body, contentType, probeText, _ string) bodyAssessment {
	a := bodyAssessment{
		text:    body,
		score:   scoreResponse(body),
		entropy: shannonEntropy(body),
		class:   classifyResponse(body, contentType),
	}
	a.band = entropyBand(a.entropy)
	a.containsMetadata = MetadataPattern.MatchString(body)
	a.containsAwsKey = AwsKeyPattern.MatchString(body)
	a.containsGcpToken = GcpTokenPattern.MatchString(body)
	a.containsInternal = InternalBodyPattern.MatchString(body)
	for _, p := range PromptInjectionPatterns {
		if m := p.FindString(body); m != "" {
			a.promptInjectMatch = m
			a.promptInjectConf = echoFactor(m, probeText)
			break
		}
	}
	return a
}
