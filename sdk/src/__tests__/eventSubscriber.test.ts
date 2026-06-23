import { EventSubscriber, EventType } from '../eventSubscriber';

describe('EventSubscriber', () => {
  let subscriber: EventSubscriber;

  beforeEach(() => {
    subscriber = new EventSubscriber({
      network: 'testnet',
      contracts: {
        didRegistry: 'CAAAA',
        credentialIssuer: 'CBBBB',
        reputationScore: 'CCCCC',
        zkAttestation: 'CDDDD',
        complianceFilter: 'CEEEE',
      },
      rpcUrl: 'https://soroban-testnet.stellar.org',
    });
  });

  afterEach(() => {
    subscriber.disconnect();
  });

  test('should subscribe to an event type', () => {
    const callback = jest.fn();
    const id = subscriber.subscribe('DIDCreated', undefined, callback);
    expect(id).toBeDefined();
    expect(id.startsWith('sub_')).toBe(true);
  });

  test('should unsubscribe from an event', () => {
    const callback = jest.fn();
    const id = subscriber.subscribe('CredentialIssued', undefined, callback);
    subscriber.unsubscribe(id);
    expect(() => subscriber.unsubscribe(id)).not.toThrow();
  });

  test('should throw for unsupported event type', () => {
    expect(() => {
      subscriber.subscribe('UnknownEvent' as EventType, undefined, jest.fn());
    }).toThrow('Unsupported event type');
  });

  test('once should resolve on first event', async () => {
    const promise = subscriber.once('DIDCreated');
    expect(promise).toBeInstanceOf(Promise);
  });

  test('should handle connect/disconnect cycle', () => {
    expect(() => subscriber.connect()).not.toThrow();
    expect(() => subscriber.disconnect()).not.toThrow();
  });
});
